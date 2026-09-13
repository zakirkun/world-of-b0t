// MIRROR CHROME :: link preview renderer
// Pure node:http + TS. No framework, no deps beyond the compiler.
import { createServer, IncomingMessage, ServerResponse } from 'node:http';

const PORT = Number(process.env.PORT ?? 3000);
const INTERNAL_URL = process.env.INTERNAL_URL ?? 'http://w0b-w07-internal:9000';

function send(res: ServerResponse, status: number, body: string, type = 'text/html; charset=utf-8') {
  res.writeHead(status, { 'content-type': type });
  res.end(body);
}

function json(res: ServerResponse, status: number, obj: unknown) {
  send(res, status, JSON.stringify(obj, null, 2), 'application/json; charset=utf-8');
}

const LANDING = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="lab" content="w07">
<title>MIRROR CHROME :: link preview renderer</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; background:#05050c; color:#c8faff; font-family:"JetBrains Mono",ui-monospace,monospace;
         min-height:100vh; padding:48px 20px; }
  .wrap { max-width:760px; margin:0 auto; }
  h1 { color:#00f0ff; letter-spacing:4px; font-size:28px; margin:0 0 4px;
       text-shadow:0 0 12px #00f0ff88; }
  h1 span { color:#ff2e97; text-shadow:0 0 12px #ff2e9788; }
  .sub { color:#5b6b8a; font-size:12px; letter-spacing:2px; margin-bottom:32px; }
  .card { border:1px solid #16233d; background:#080a14; padding:22px; border-radius:4px; position:relative; }
  .card::before { content:""; position:absolute; inset:-1px auto auto -1px; width:34px; height:2px; background:#00f0ff; }
  label { display:block; font-size:11px; color:#5b6b8a; letter-spacing:2px; margin-bottom:10px; }
  input[type=text] { width:100%; background:#05050c; border:1px solid #1d2c4a; color:#00f0ff;
                     padding:12px 14px; font-family:inherit; font-size:14px; outline:none; }
  input[type=text]:focus { border-color:#00f0ff; box-shadow:0 0 10px #00f0ff44; }
  button { margin-top:16px; background:transparent; border:1px solid #ff2e97; color:#ff2e97;
           padding:11px 26px; font-family:inherit; font-size:13px; letter-spacing:3px; cursor:pointer; }
  button:hover { background:#ff2e97; color:#05050c; box-shadow:0 0 18px #ff2e9788; }
  pre { background:#040409; border:1px solid #16233d; padding:16px; overflow:auto; max-height:420px;
        font-size:12px; color:#8fe9ff; white-space:pre-wrap; word-break:break-all; }
  .note { margin-top:26px; font-size:11px; color:#4a5875; line-height:1.7; }
  a { color:#00f0ff; }
</style>
</head>
<body>
<div class="wrap">
  <h1>MIRROR <span>CHROME</span></h1>
  <div class="sub">// LINK PREVIEW RENDERER :: v0.7.3</div>

  <div class="card">
    <label>SOURCE URL</label>
    <form method="POST" action="/fetch">
      <input type="text" name="url" placeholder="https://example.com/article" autocomplete="off">
      <button type="submit">MIRROR</button>
    </form>
  </div>

  <div class="note">
    Paste a link and MIRROR CHROME pulls the page through our <b>internal render farm</b>
    and hands back the raw preview.<br>
    Status: <span style="color:#00f0ff">ONLINE</span> &nbsp;|&nbsp; Node: <span style="color:#ff2e97">render-01</span>
  </div>
</div>
</body>
</html>`;

// ponytail: fetch with a hard timeout so a black-holed URL can't hang a worker
async function mirror(target: string) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 8000);
  try {
    const r = await fetch(target, { redirect: 'follow', signal: ac.signal });
    const text = await r.text();
    return { status: r.status, headers: Object.fromEntries(r.headers), body: text.slice(0, 4096) };
  } finally {
    clearTimeout(t);
  }
}

function renderResult(r: { status: number; body: string }): string {
  return LANDING.replace(
    '</div>\n</body>',
    `</div>
  <div class="card" style="margin-top:22px">
    <label>PREVIEW :: HTTP ${r.status}</label>
    <pre>${r.body.replace(/[<>&]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c] as string))}</pre>
  </div>
</div>
</body>`
  );
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let d = '';
    req.on('data', (c) => (d += c));
    req.on('end', () => resolve(d));
  });
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://x');

  if (req.method === 'GET' && url.pathname === '/') return send(res, 200, LANDING);

  if (req.method === 'GET' && url.pathname === '/robots.txt')
    return send(res, 200, 'User-agent: *\nDisallow: /fetch\nDisallow: /api\n', 'text/plain; charset=utf-8');

  // ponytail: ops convenience endpoint. Says nothing about HOW to reach internals,
  // just enough for an attacker to notice there is an internal render farm.
  if (req.method === 'GET' && url.pathname === '/api/health')
    return json(res, 200, {
      service: 'mirror-chrome',
      version: '0.7.3',
      uptime: Math.floor(process.uptime()),
      renderfarm: 'internal',
      upstream_host: new URL(INTERNAL_URL).host,
    });

  if (req.method === 'POST' && url.pathname === '/fetch') {
    let target = '';
    const raw = await readBody(req);
    const ct = req.headers['content-type'] ?? '';
    if (ct.includes('application/json')) {
      try { target = (JSON.parse(raw) as { url?: string }).url ?? ''; } catch { /* fall through */ }
    } else {
      target = new URLSearchParams(raw).get('url') ?? '';
    }

    if (!target) return json(res, 400, { error: 'missing url' });

    // VULNERABLE: no allowlist, no private-range check, no scheme check.
    // file://, http://127.0.0.1, http://localhost and internal docker
    // hostnames are all happily fetched. That's the lab.
    try {
      const r = await mirror(target);
      if ((req.headers.accept ?? '').includes('application/json'))
        return json(res, 200, { target, ...r });
      return send(res, 200, renderResult(r));
    } catch (e) {
      return json(res, 502, { target, error: String((e as Error).message) });
    }
  }

  return send(res, 404, 'not found', 'text/plain; charset=utf-8');
});

server.listen(PORT, () => console.log(`mirror-chrome listening on :${PORT} (renderfarm ${INTERNAL_URL})`));
