// MIRROR CHROME :: internal render farm
// Network-isolated. No host port is published for this service; the only way in
// is from another container on the w0b network — i.e. through the web app's SSRF.
const { createServer } = require('node:http');

const PORT = Number(process.env.PORT ?? 9000);
const FLAG = process.env.W0B_FLAG ?? 'hex4b0t{REPLACED_AT_RUNTIME}';

const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://x');

  if (url.pathname === '/secret') {
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
    return res.end(JSON.stringify({ flag: FLAG }));
  }

  if (url.pathname === '/health') {
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
    return res.end(JSON.stringify({ service: 'w07-internal', ok: true }));
  }

  res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('not found');
});

server.listen(PORT, '0.0.0.0', () => console.log(`internal render farm on :${PORT}`));
