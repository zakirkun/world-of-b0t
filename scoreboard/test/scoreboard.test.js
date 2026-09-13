'use strict';

// Scoreboard self-check. Run:  node test/scoreboard.test.js
//
// Exercises the paths the 5-part task added: flags sync from JSON into SQLite,
// submit verifying against SQLite (not the file), duplicate handling, points by
// difficulty, and the MCP JSON-RPC surface. Uses an in-memory DB + a temp flags
// file so it never touches the real scoreboard.
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'w0b-test-'));
const flagsFile = path.join(tmp, 'flags.json');
fs.writeFileSync(
  flagsFile,
  JSON.stringify({ w01: 'hex4b0t{aaaa111122223333}', w20: 'hex4b0t{bbbb444455556666}' })
);

process.env.DB_PATH = path.join(tmp, 'test.db');
process.env.FLAGS_PATH = flagsFile;

const { db, submitFlag, mcpHandle, POINTS } = require('../server.js');

let pass = 0;
const check = (label, fn) => {
  try {
    fn();
    console.log(`  ok   ${label}`);
    pass++;
  } catch (e) {
    console.log(`  FAIL ${label}\n       ${e.message}`);
    process.exitCode = 1;
  }
};

console.log('[*] flags sync into SQLite');
check('two flags in the table', () => assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM flags').get().n, 2));
check('only hashes stored, no plaintext', () => {
  const row = db.prepare('SELECT * FROM flags WHERE lab = ?').get('w01');
  assert.strictEqual(row.flag_hash.length, 64);
  assert.ok(!JSON.stringify(row).includes('hex4b0t{'));
});

console.log('[*] submit verifies against SQLite');
check('correct flag solves w01 (easy = 100)', () => {
  const { status, body } = submitFlag({ flag: 'hex4b0t{aaaa111122223333}', team: 'ai-pilot' });
  assert.strictEqual(status, 200);
  assert.strictEqual(body.ok, true);
  assert.strictEqual(body.lab, 'w01');
  assert.strictEqual(body.points, POINTS.easy);
});
check('hard lab is worth 500', () => {
  const { body } = submitFlag({ flag: 'hex4b0t{bbbb444455556666}', team: 'ai-pilot' });
  assert.strictEqual(body.lab, 'w20');
  assert.strictEqual(body.points, POINTS.hard);
});
check('wrong flag rejected 403', () => {
  const { status, body } = submitFlag({ flag: 'hex4b0t{deadbeefdeadbeef}', team: 'ai-pilot' });
  assert.strictEqual(status, 403);
  assert.strictEqual(body.ok, false);
});
check('duplicate solve refused', () => {
  const { body } = submitFlag({ flag: 'hex4b0t{aaaa111122223333}', team: 'ai-pilot' });
  assert.strictEqual(body.duplicate, true);
});
check('missing team rejected 400', () => {
  const { status } = submitFlag({ flag: 'hex4b0t{aaaa111122223333}' });
  assert.strictEqual(status, 400);
});

console.log('[*] MCP surface');
check('initialize reports serverInfo', () => {
  const r = mcpHandle({ jsonrpc: '2.0', id: 1, method: 'initialize' });
  assert.strictEqual(r.result.serverInfo.name, 'w0b-labs');
});
check('tools/list exposes submit_flag', () => {
  const r = mcpHandle({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const names = r.result.tools.map((t) => t.name);
  assert.ok(names.includes('submit_flag'), `got ${names}`);
  assert.ok(names.includes('list_labs'));
});
check('tools/call list_labs returns the catalogue', () => {
  const r = mcpHandle({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'list_labs', arguments: {} } });
  const payload = JSON.parse(r.result.content[0].text);
  assert.ok(payload.count >= 20, `expected 20 labs, got ${payload.count}`);
  assert.ok(payload.labs.every((l) => typeof l.points === 'number'));
});
check('tools/call submit_flag with a wrong flag is a result, not a crash', () => {
  const r = mcpHandle({
    jsonrpc: '2.0',
    id: 4,
    method: 'tools/call',
    params: { name: 'submit_flag', arguments: { flag: 'hex4b0t{nope0000000000000}', team: 'mcp-bot' } },
  });
  // A rejected flag is a normal answer the bot can read, not a transport error.
  assert.strictEqual(r.result.isError, false);
  const payload = JSON.parse(r.result.content[0].text);
  assert.strictEqual(payload.ok, false);
  assert.strictEqual(payload.http_status, 403);
});
check('tools/call submit_flag through MCP awards points', () => {
  const r = mcpHandle({
    jsonrpc: '2.0',
    id: 7,
    method: 'tools/call',
    params: { name: 'submit_flag', arguments: { flag: 'hex4b0t{aaaa111122223333}', team: 'mcp-bot' } },
  });
  const payload = JSON.parse(r.result.content[0].text);
  assert.strictEqual(payload.ok, true);
  assert.strictEqual(payload.points, POINTS.easy);
});
check('a genuinely bad tool name is an in-band error', () => {
  const r = mcpHandle({ jsonrpc: '2.0', id: 8, method: 'tools/call', params: { name: 'does_not_exist', arguments: {} } });
  assert.strictEqual(r.result.isError, true);
});
check('tools/call get_leaderboard shows the bot', () => {
  const r = mcpHandle({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'get_leaderboard', arguments: {} } });
  const lb = JSON.parse(r.result.content[0].text).leaderboard;
  assert.ok(lb.find((t) => t.team === 'ai-pilot'));
});
check('unknown method -> -32601', () => {
  const r = mcpHandle({ jsonrpc: '2.0', id: 6, method: 'nope' });
  assert.strictEqual(r.error.code, -32601);
});

console.log(`\n[${process.exitCode ? '!' : '+'}] ${pass} checks passed`);

// Close the DB before cleanup - Windows keeps the WAL file locked otherwise.
db.close();
try {
  fs.rmSync(tmp, { recursive: true, force: true });
} catch {
  /* temp dir is disposable; leave it if Windows still holds the handle */
}
