# w23 :: Dossier Trace

- **Category:** OSINT
- **Difficulty:** medium
- **Stack:** Python 3 (stdlib http.server, single container)
- **URL:** http://localhost:30023

## Brief

NAKTA LOGISTICS went out of business in 2019, but its employee portal is still
up on a retained, read-only snapshot. Nobody patched a dead portal. The staff
directory, an HR memo, and a few leftover posts are all still there — published
to anyone who asks the crawler-adjacent questions.

The flag is not written on any page. It is behind a route this snapshot does
not advertise. OSINT is the art of asking dead systems the right questions.

Where OSINT hunters start on a domain:

| artifact | classic path |
|---|---|
| `robots.txt` | crawlers were told what exists |
| `/.well-known/security.txt` | who ran security, what domains matter |
| response headers | what served the page, and what it is a snapshot **of** |
| comment / metadata breadcrumbs | what moved where, and when |

## Goal

Correlate the public artifacts into a pivot the portal still honors, and reach
the flag. Chain shape (you discover the specifics yourself):

`something the crawlers were told about` -> `a snapshot that names a person`
-> `a memo that explains how such people are addressed` -> `a board post that
gives the derivation` -> `the unlisted route`.

## Hint

Every page on this server names something concrete: a company, a project, a
badge, an email. Enumerate the classic first-touch files first — you will find
two directories the portal still serves but the landing page only half-names.
The staff board is addressed the way the memo says, not the way you'd guess.

<details>
<summary>Spoiler</summary>

1. `/robots.txt` still disallows `/archive/` and `/hr/` — both are served.
2. `/archive/` is a "wayghost mirror" of the 2019-11 staff directory (the
   `X-Wayghost-Snapshot` header confirms what it is). One badge matters:
   **Rani Prasetyo, NP4471**, departed 2019-09-30.
3. `/hr/offboarding.txt` explains the addressing convention: staff boards live
   at `/board/<badge>` — no dash — and departed staff "keep their own notes
   wherever they like". HR cannot audit that.
4. `/board/NP4471` holds a leftover post: the glyph path is
   `/glyph/<first 8 hex chars of sha256 of my badge id>`.
5. Derive and fetch:

```bash
glyph=$(printf NP4471 | sha256sum | cut -c1-8)
curl -s "http://localhost:30023/glyph/$glyph"
# DOSSIER COMPLETE — hex4b0t{...}
```

`solution/exploit.sh` walks all five stages; `solution/probe.sh` asserts each
stage works and that unlisted/undiscovered routes do not leak.

</details>
