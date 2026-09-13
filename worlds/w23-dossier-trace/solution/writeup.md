# w23 Dossier Trace :: solution

## Root cause

`app/server.py`, the `/glyph/` route:

```python
elif path.startswith("/glyph/"):
    code = path[len("/glyph/"):]
    # VULNERABLE: the route is unlisted but deterministic — the glyph
    # code is derivable entirely from artifacts this server exposes.
    if code == GLYPH:
```

with, at the top of the file:

```python
BADGE = "NP4471"
GLYPH = hashlib.sha256(BADGE.encode()).hexdigest()[:8]
```

Unlisted is not secret. Every input to the derivation is published by the same
server that keeps the route: a badge id on a staff directory snapshot, an HR
memo describing how boards are addressed, and a departing employee's leftover
board post spelling out the derivation itself. A decommissioned portal is not a
patched portal — nobody ever came back to remove what the crawlers and the
company's own people left behind.

## Recon

Landing page points at `/robots.txt`, `/.well-known/security.txt`, and the
archive. Start where every OSINT engagement starts:

```bash
curl -s http://localhost:30023/robots.txt
# User-agent: *
# Disallow: /archive/
# Disallow: /hr/
```

Two directories the crawler was told about. Both still serve. `security.txt`
names the domain and the CMS in the landing page's `<meta name="generator">`
(`nakta-cms 2.1`) — flavor, but it confirms this is a coherent corporate
footprint, not a random server.

## Exploit

**Stage 1 — the archive.** `/archive/` is a "wayghost mirror" of the staff
directory, snapshot 2019-11-02 (the `X-Wayghost-Snapshot` response header says
the same). Three employees; one is flagged `departed 2019-09-30`:

```
Rani Prasetyo   NP4471   freight sync   departed 2019-09-30
```

**Stage 2 — the memo.** `/hr/offboarding.txt` (the second disallowed path) is
an offboarding checklist. Three load-bearing lines:

- staff boards are addressed by badge id, no dash: `/board/<badge>`
- departing staff must clear their staff-board posts; anything left behind is
  retained
- personal sync keys are never stored in HR systems — "we cannot audit that"

**Stage 3 — the board.** Address it the way the memo says:

```bash
curl -s http://localhost:30023/board/NP4471
```

The departed employee left a personal note on her board:

```
glyph path is /glyph/<first 8 hex chars of sha256 of my badge id>
```

**Stage 4 — derive.**

```bash
glyph=$(printf NP4471 | sha256sum | cut -c1-8)
# ed8b8972
curl -s "http://localhost:30023/glyph/$glyph"
# <h1>DOSSIER COMPLETE</h1><p>hex4b0t{...}</p>
```

`solution/exploit.sh` walks all five stages and prints the flag.

## Dead ends worth recording

**Brute-forcing `/glyph/`.** 8 hex chars = 4.3 billion values. The derivation
is published; enumeration is not the intended path and would never finish
anyway.

**Boards of active staff.** `/board/NP0000` and `/board/NP2210` exist but hold
no posts. The memo's retention language ("anything left behind") is the tell
that the departed employee's board is the one with something on it.

**Looking for the flag in page text.** No page contains `hex4b0t{`. `grep` the
whole surface and you find only the breadcrumb nouns — the flag requires the
derivation, which is the OSINT point.

**The email address.** `r.prasetyo@nakta-logistics.local` confirms the
naming convention but is not itself a pivot — the badge id is.

## The fix

**1. Delete, don't decommission.** Retention policy 7.3 kept the records
readable forever. For routes that are part of a secret (`/glyph/`), retention
is indistinguishable from publication: if a route must stay derivable, its
derivation inputs must not be co-located on the same public surface.

**2. Never publish the derivation next to the inputs.** The board post is the
whole bug compressed into one paragraph: badge id (from the archive) +
algorithm (from the post) + route shape (from the memo), all on one server.
Split-brain secrets — inputs here, algorithm elsewhere — at least raise the
cost; a derived code with no expiry at all is the real failure.

**3. Rotating codes.** A glyph derived from a static badge id never expires.
Any code that protects a route needs rotation independent of the identifier it
is derived from.

The general lesson: **OSINT failures are correlation failures.** Each artifact
is individually harmless — a directory, a memo, a farewell note. The vuln is
that they were all left reachable from one domain, in one snapshot, forever.

## Flag

Injected at runtime into the container's `W0B_FLAG`; served only by the
`/glyph/<code>` route, which no page links to and no robots entry admits.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
