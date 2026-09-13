'use strict';

// MCP stdio wrapper for the World Of B0t scoreboard.
//
// Speaks JSON-RPC 2.0 over stdin/stdout (newline-delimited) and forwards every
// request to the running scoreboard's HTTP /mcp endpoint. This lets a local AI
// bot (Claude Desktop, Claude Code, any MCP client) attach with:
//
//   {
//     "mcpServers": {
//       "w0b-labs": { "command": "node", "args": ["<repo>/scoreboard/mcp-stdio.js"] }
//     }
//   }
//
// The bot then gets list_labs / get_lab / submit_flag / get_leaderboard /
// get_solves as tools, and reaches the labs over their published URLs.
//
// ponytail: a thin proxy, not a second implementation. All logic lives in
// server.js so website, REST, HTTP-MCP, and stdio-MCP can never drift.
const http = require('http');

const HOST = process.env.SCOREBOARD_HOST || '127.0.0.1';
const PORT = Number(process.env.SCOREBOARD_PORT || process.env.PORT || 30000);

function forward(msg) {
  return new Promise((resolve) => {
    const body = JSON.stringify(msg);
    const req = http.request(
      { host: HOST, port: PORT, path: '/mcp', method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          if (res.statusCode === 202 || !data) return resolve(null);
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve({ jsonrpc: '2.0', id: msg.id ?? null, error: { code: -32603, message: 'bad response from scoreboard' } });
          }
        });
      }
    );
    req.on('error', (e) =>
      resolve({ jsonrpc: '2.0', id: msg.id ?? null, error: { code: -32000, message: `scoreboard unreachable at ${HOST}:${PORT} (${e.message}) - run 'manage.ps1 up'` } })
    );
    req.write(body);
    req.end();
  });
}

function send(obj) {
  if (obj) process.stdout.write(JSON.stringify(obj) + '\n');
}

// Responses must be written in request order and the process must not exit
// until every in-flight request has been answered - so dispatch each line to a
// promise and keep the chain serial.
let buf = '';
const inflight = [];

function dispatch(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  inflight.push(forward(msg).then(send));
}

process.stdin.on('data', (chunk) => {
  buf += chunk.toString('utf8');
  let nl;
  while ((nl = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (line) dispatch(line);
  }
});

// stdin closed: no more requests, but keep the process alive until all replies
// have been written. `process.stdin.on('end')` plus a pending count is the only
// reliable signal here - node would otherwise exit mid-request.
process.stdin.on('end', () => {
  Promise.all(inflight).then(() => process.exit(0));
});

// Reachability note on stderr only - stdout is the protocol channel.
process.stderr.write(`[w0b-mcp] stdio bridge -> http://${HOST}:${PORT}/mcp\n`);
