#!/usr/bin/env python3
# DOSSIER TRACE :: open-source intelligence trail (World Of B0t challenge 23)
# Category: OSINT | Difficulty: medium
# Vuln: decommissioned portal leaves internal artifacts exposed; correlating
#       them (robots.txt -> archive -> HR memo -> staff board) yields a pivot
#       to a hidden route that holds the flag.
# Stdlib only. Plain http.server, like the rest of the Python labs.

import hashlib
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8080"))
FLAG = os.environ.get("W0B_FLAG", "hex4b0t{REPLACED_AT_RUNTIME}")

# ponytail: one hard-coded persona. If you fork this lab, rotate the badge and
# the board-post text together — the glyph route derives from the badge.
BADGE = "NP4471"
GLYPH = hashlib.sha256(BADGE.encode()).hexdigest()[:8]

SECURITY_TXT = """Contact: mailto:security@nakta-logistics.local
Expires: 2027-01-01T00:00:00Z
Preferred-Languages: en, id
Canonical: /.well-known/security.txt
"""

ROBOTS = """User-agent: *
Disallow: /archive/
Disallow: /hr/

# crawler questions -> security@nakta-logistics.local
# decommissioned 2019; retained records are read-only
"""

LANDING = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="lab" content="w23">
<meta name="generator" content="nakta-cms 2.1">
<title>NAKTA LOGISTICS :: employee portal</title>
<style>
  body {{ background:#05050c; color:#cfd8e3; font-family:ui-monospace,Consolas,monospace;
         margin:0; padding:4rem 1rem; }}
  a {{ color:#00f0ff; }}
  .frame {{ max-width:760px; margin:0 auto; border:1px solid #1c2333; padding:2rem; }}
  h1 {{ color:#00f0ff; letter-spacing:2px; margin-top:0; }}
  .tag {{ color:#ff2e97; font-size:12px; letter-spacing:1px; }}
  .muted {{ color:#5b6b80; font-size:13px; }}
  input {{ background:#0a0e18; border:1px solid #1c2333; color:#cfd8e3;
           font-family:inherit; padding:.5rem; width:60%; }}
  button {{ background:#0a0e18; border:1px solid #00f0ff; color:#00f0ff;
            font-family:inherit; padding:.5rem 1rem; cursor:pointer; }}
</style>
</head>
<body>
<div class="frame">
  <div class="tag">NAKTA LOGISTICS // freight sync division</div>
  <h1>EMPLOYEE PORTAL</h1>
  <p class="muted">This portal was decommissioned in 2019. The company no longer
     operates, but per retention policy 7.3 the records below remain readable.</p>
  <p>
    <input placeholder="employee search..." disabled>
    <button disabled>search</button>
  </p>
  <p class="muted">search is offline. staff directory snapshots live in the
     <a href="/archive/">archive</a>. crawler policy: <a href="/robots.txt">/robots.txt</a></p>
  <p class="muted">security contact: <a href="/.well-known/security.txt">/.well-known/security.txt</a></p>
  <p class="tag">wayghost project mirror :: snapshot integrity verified</p>
</div>
</body>
</html>
"""

ARCHIVE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>wayghost mirror :: nakta staff directory 2019-11</title>
<style>
  body {{ background:#05050c; color:#cfd8e3; font-family:ui-monospace,Consolas,monospace;
         margin:0; padding:3rem 1rem; }}
  h1 {{ color:#00f0ff; font-size:18px; letter-spacing:1px; }}
  table {{ border-collapse:collapse; margin-top:1rem; }}
  td, th {{ border:1px solid #1c2333; padding:.4rem .9rem; font-size:14px; }}
  th {{ color:#ff2e97; text-align:left; }}
</style>
</head>
<body>
<h1>STAFF DIRECTORY — snapshot 2019-11-02</h1>
<!-- wayghost snapshot 2019-11-02 :: captured from /hr/directory before the portal closed -->
<table>
  <tr><th>name</th><th>badge</th><th>role</th><th>status</th></tr>
  <tr><td>Bayu Setiawan</td><td>NP0000</td><td>dock coordinator</td><td>active</td></tr>
  <tr><td>Rani Prasetyo</td><td>NP4471</td><td>freight sync</td><td>departed 2019-09-30</td></tr>
  <tr><td>Dewi Anggraini</td><td>NP2210</td><td>customs liaison</td><td>active</td></tr>
</table>
<p style="color:#5b6b80;font-size:13px">staff board boards are addressed by badge id.</p>
</body>
</html>
"""

MEMO = """NAKTA LOGISTICS :: HR MEMO 2019-09-30
RE: offboarding checklist (draft - do not circulate)

- corporate mailboxes stay readable for 12 months
  (mailbox naming: first initial + last name, e.g. r.prasetyo@nakta-logistics.local)
- departing staff must clear their staff-board posts before last day;
  anything left behind is retained per policy 7.3
- staff boards are addressed by badge id, no dash: /board/<badge>
- personal sync keys are NEVER stored in HR systems.
  staff keep their own notes wherever they like. we cannot audit that.

signed,
rani p. — freight sync, badge NP4471 (last day)
"""

BOARD = """STAFF BOARD :: badge NP4471
handle: rani p. &lt;r.prasetyo@nakta-logistics.local&gt;

post #3 --- 2019-09-28
  two days to last shift. keeping my personal sync note here so I don't
  lose it when the laptop goes back:

    glyph path is /glyph/<first 8 hex chars of sha256 of my badge id>

  lowercase hex. that's the whole note. if HR reads this - it's a bookmark,
  not a key. (they never audit the board. see memo 7.3.)
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "nakta-httpd/2.1"
    sys_version = ""

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"

        if path == "/":
            self._send(200, LANDING)
        elif path == "/robots.txt":
            self._send(200, ROBOTS, "text/plain; charset=utf-8")
        elif path == "/.well-known/security.txt":
            self._send(200, SECURITY_TXT, "text/plain; charset=utf-8")
        elif path == "/archive":
            # ponytail: header flavor for the header-recon crowd; the real
            # breadcrumbs are in the page body.
            self._send(200, ARCHIVE, extra={"X-Wayghost-Snapshot": "2019-11-02"})
        elif path == "/hr/offboarding.txt":
            self._send(200, MEMO, "text/plain; charset=utf-8")
        elif path.startswith("/board/"):
            badge = path[len("/board/"):]
            if badge == BADGE:
                self._send(200, BOARD)
            elif badge in ("NP0000", "NP2210"):
                self._send(200, "STAFF BOARD :: badge %s\n\nno posts on this board.\n" % badge,
                           "text/plain; charset=utf-8")
            else:
                self._send(404, "no such board.\n", "text/plain; charset=utf-8")
        elif path.startswith("/glyph/"):
            code = path[len("/glyph/"):]
            # VULNERABLE: the route is unlisted but deterministic — the glyph
            # code is derivable entirely from artifacts this server exposes.
            if code == GLYPH:
                self._send(200,
                           "<!doctype html><html><head><meta charset=\"utf-8\">"
                           "<title>dossier complete</title></head><body>"
                           "<h1>DOSSIER COMPLETE</h1><p>%s</p></body></html>" % FLAG,
                           extra={"X-Dossier-Complete": "true"})
            else:
                self._send(404, "no such glyph.\n", "text/plain; charset=utf-8")
        elif path == "/api/health":
            import json
            self._send(200, json.dumps({"ok": True, "lab": "w23", "archive": True}),
                       "application/json")
        else:
            self._send(404, "not found.\n", "text/plain; charset=utf-8")

    def log_message(self, fmt, *args):
        pass  # keep container logs quiet


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
