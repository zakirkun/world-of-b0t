'use strict';

/**
 * DATA JACK :: archives index
 * World Of B0t challenge 05
 * Category: Web | Difficulty: medium | Vuln: blind SQL injection (boolean-based)
 *
 * The search endpoint answers exactly one bit per request: found / not found.
 * No rows, no errors, no counts. The flag lives in a table the search query
 * never touches, so it has to be pulled out one yes/no question at a time.
 */

const express = require('express');
const Database = require('better-sqlite3');

const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || '/tmp/data-jack.db';
const FLAG = process.env.W0B_FLAG || 'hex4b0t{missing_flag}';

// ---------------------------------------------------------------------------
// Database (a file, not :memory: - seeded once at boot)
// ---------------------------------------------------------------------------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS records (
    id    INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    tag   TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS vault (
    id     INTEGER PRIMARY KEY,
    secret TEXT NOT NULL
  );
`);

db.prepare('DELETE FROM records').run();
db.prepare('DELETE FROM vault').run();

const seedRecords = db.prepare('INSERT INTO records (id, title, tag) VALUES (?, ?, ?)');
for (const r of [
  [1, 'neon ledger fragment', 'finance'],
  [2, 'chrome district manifest', 'logistics'],
  [3, 'ghost protocol notes', 'intel'],
  [4, 'zer0 day auction list', 'blackmarket'],
  [5, 'archive index mirror', 'archive'],
  [6, 'decommissioned relay keys', 'infra'],
]) {
  seedRecords.run(...r);
}

// The prize. Never reachable through /search's own table.
db.prepare('INSERT INTO vault (id, secret) VALUES (?, ?)').run(1, FLAG);

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express();

const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="lab" content="w05">
<title>DATA JACK :: archives index</title>
<style>
 :root{--bg:#05050c;--cy:#00f0ff;--mg:#ff2e97;--dim:#4a5f70;--fg:#cfefff}
 *{box-sizing:border-box}
 body{margin:0;min-height:100vh;padding-block:40px;padding-inline:16px;background:var(--bg);
   color:var(--fg);font:14px/1.6 "SF Mono",Consolas,"Courier New",monospace;
   background-image:linear-gradient(rgba(0,240,255,.035) 1px,transparent 1px),
                    linear-gradient(90deg,rgba(0,240,255,.035) 1px,transparent 1px);
   background-size:44px 44px}
 .wrap{max-width:820px;margin:0 auto}
 header{border-bottom:1px solid #10384a;padding-bottom:20px;margin-bottom:28px}
 h1{margin:0;font-size:clamp(22px,5vw,34px);letter-spacing:6px;color:var(--cy);
   text-shadow:0 0 14px rgba(0,240,255,.65)}
 h1 span{color:var(--mg);text-shadow:0 0 14px rgba(255,46,151,.65)}
 .sub{color:var(--dim);font-size:11px;letter-spacing:3px;margin-top:8px}
 .panel{border:1px solid #10384a;border-radius:12px;background:#080810;
   box-shadow:0 0 40px rgba(0,240,255,.08);padding:22px;margin-bottom:22px}
 .panel h2{margin:0 0 14px;font-size:12px;letter-spacing:3px;color:var(--mg);font-weight:400}
 .row{display:flex;gap:10px;flex-wrap:wrap}
 input{flex:1 1 240px;min-width:0;padding:12px;border-radius:6px;background:#050510;
   border:1px solid #16324a;color:var(--fg);font:inherit}
 input:focus{outline:none;border-color:var(--cy);box-shadow:0 0 0 3px rgba(0,240,255,.12)}
 button{padding:12px 22px;border-radius:6px;cursor:pointer;letter-spacing:2px;
   background:rgba(0,240,255,.1);border:1px solid var(--cy);color:var(--cy);font:inherit}
 button:hover{background:rgba(0,240,255,.2);box-shadow:0 0 18px rgba(0,240,255,.35)}
 table{width:100%;border-collapse:collapse;font-size:12.5px}
 th{text-align:left;color:var(--dim);font-weight:400;letter-spacing:2px;font-size:10px;
   padding:8px 10px;border-bottom:1px solid #10384a}
 td{padding:9px 10px;border-bottom:1px solid #0d1a24}
 td.tag{color:var(--mg)}
 .note{color:var(--dim);font-size:11px;line-height:1.9}
 code{color:#ffe600}
 a{color:var(--cy)}
 footer{color:#2b3a47;font-size:10px;letter-spacing:2px;text-align:center;margin-top:26px}
</style></head><body><div class="wrap">
<header>
  <h1>DATA <span>JACK</span></h1>
  <div class="sub">// archives index :: world of b0t :: w05</div>
</header>
<div class="panel">
  <h2>&gt; SEARCH ARCHIVES</h2>
  <form method="get" action="/search">
    <div class="row">
      <input name="q" placeholder="exact tag to look up..." autocomplete="off" spellcheck="false" autofocus>
      <button type="submit">JACK IN</button>
    </div>
  </form>
</div>
<div class="panel">
  <h2>&gt; INDEX CONTENTS</h2>
  <table><thead><tr><th>ID</th><th>TITLE</th><th>TAG</th></tr></thead><tbody>
  __ROWS__
  </tbody></table>
</div>
<div class="panel">
  <h2>&gt; SYSTEM NOTE</h2>
  <div class="note">
    The index endpoint returns a single boolean. It will not hand you rows,<br>
    it will not hand you errors, and it will not hand you a map.<br>
    Lookup is an exact match on <code>tag</code>. There is a <code>vault</code><br>
    the index was never wired to list.<br>
    Ask the database one yes/no question at a time.
  </div>
</div>
<footer>d4t4_j4ck :: node/express :: index v0.5</footer>
</div></body></html>`;

const rowsHtml = () =>
  db
    .prepare('SELECT id, title, tag FROM records ORDER BY id')
    .all()
    .map(
      (r) =>
        `<tr><td>${r.id}</td><td>${r.title}</td><td class="tag">${r.tag}</td></tr>`
    )
    .join('');

app.get('/', (_req, res) => {
  res.type('html').send(PAGE.replace('__ROWS__', rowsHtml()));
});

// ---------------------------------------------------------------------------
// VULNERABLE ENDPOINT
//
//   SELECT id FROM records WHERE tag = '<q>'
//
// The tag index is an exact-match lookup, so an unmatched tag yields no row and
// the handler reports `{found:false}`. Errors are swallowed into the same
// shape, so nothing but the bit leaks - no rows, no error text, no counts.
// ---------------------------------------------------------------------------
app.get('/search', (req, res) => {
  // Array params (?q=a&q=b) would blow up better-sqlite3's binding - normalise
  // to a string so the query string is the only thing that ever reaches SQL.
  const q = typeof req.query.q === 'string' ? req.query.q : '';

  let found = false;
  try {
    // String interpolation. No parameterisation. This is the bug.
    const row = db.prepare(`SELECT id FROM records WHERE tag = '${q}'`).get();
    found = row !== undefined;
  } catch {
    found = false;
  }

  // Only ever a bit.
  res.type('application/json').send(JSON.stringify({ found }));
});

app.get('/robots.txt', (_req, res) => {
  res.type('text/plain').send('User-agent: *\nDisallow: /vault\nDisallow: /search\n');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`DATA JACK online :: index on http://0.0.0.0:${PORT}`);
});
