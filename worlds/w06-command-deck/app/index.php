<?php
// COMMAND DECK :: packet console
// World Of B0t challenge 06
// Category: Web | Difficulty: medium | Vuln: Command injection
//
// A tiny ops tool: it runs `ping` and `traceroute` from the deck's own host and
// prints the raw output. The host field is what the operator types next to the
// buttons; the tools do not validate it because "the console is internal".

const LAB_VERSION = '0.6.4';

// Flag lives in this process's environment, never in a file the web server can
// serve. Reading it therefore requires command execution, not path guessing.
function lab_flag(): string
{
    $flag = getenv('W0B_FLAG');
    return ($flag === false || $flag === '') ? 'hex4b0t{REPLACED_AT_RUNTIME}' : $flag;
}

$tool = $_POST['tool'] ?? $_GET['tool'] ?? 'ping';
$host = $_POST['host'] ?? $_GET['host'] ?? '';
$out  = null;

$allowed = ['ping', 'traceroute'];

if ($host !== '' && in_array($tool, $allowed, true)) {
    // ponytail: the tool name is whitelisted and the host is quoted, but the
    // count is pasted in raw "because it is a number" -- there is no numeric
    // validation, so the shell sees whatever the operator typed.
    $opt = $tool === 'ping' ? '-c' : '-m';
    $cmd = $tool . ' ' . $opt . ' ' . ($_POST['count'] ?? $_GET['count'] ?? '1') . ' ' . escapeshellarg($host);

    // ponytail: one string, one shell. This is the command injection: the
    // caller controls `count`, which is concatenated into the command line
    // with no escaping and no validation.
    $out = shell_exec($cmd . ' 2>&1');
}

$host_attr = htmlspecialchars($host, ENT_QUOTES);
$count_attr = htmlspecialchars((string)($_POST['count'] ?? $_GET['count'] ?? '1'), ENT_QUOTES);
$out_html = $out === null ? '' : htmlspecialchars($out, ENT_QUOTES);
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="lab" content="w06">
<title>COMMAND DECK // packet console</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 32px 20px;
    background: #05050c; color: #cfe9ff;
    font: 14px/1.5 "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  }
  a { color: #00f0ff; }
  header { max-width: 860px; margin: 0 auto 24px; }
  h1 { margin: 0; font-size: 26px; letter-spacing: 3px; color: #00f0ff;
       text-shadow: 0 0 12px rgba(0,240,255,.55); }
  .sub { color: #ff2e97; letter-spacing: 1px; font-size: 12px; text-transform: uppercase; }
  .bar { height: 2px; margin: 14px 0;
         background: linear-gradient(90deg, #00f0ff, #ff2e97 60%, transparent); }
  main, footer { max-width: 860px; margin: 0 auto; }
  .card { border: 1px solid rgba(0,240,255,.35); background: rgba(0,240,255,.04);
          padding: 18px; margin-bottom: 18px; }
  .card h2 { margin: 0 0 12px; font-size: 13px; letter-spacing: 2px;
             color: #00f0ff; text-transform: uppercase; }
  label { display: block; margin: 10px 0 4px; font-size: 12px; color: #7aa7c7; }
  input[type=text] {
    width: 100%; padding: 9px 10px; background: #0a0a18; color: #cfe9ff;
    border: 1px solid rgba(0,240,255,.35); font: inherit;
  }
  input[type=text]:focus { outline: none; border-color: #ff2e97;
                           box-shadow: 0 0 10px rgba(255,46,151,.35); }
  .row { display: flex; gap: 14px; flex-wrap: wrap; }
  .row > div { flex: 1 1 200px; }
  .tools { display: flex; gap: 10px; margin-top: 14px; flex-wrap: wrap; }
  button {
    padding: 9px 18px; background: transparent; color: #00f0ff; cursor: pointer;
    border: 1px solid #00f0ff; font: inherit; letter-spacing: 1px;
  }
  button:hover { background: #00f0ff; color: #05050c; }
  button.alt { color: #ff2e97; border-color: #ff2e97; }
  button.alt:hover { background: #ff2e97; color: #05050c; }
  pre { margin: 0; padding: 14px; overflow-x: auto; background: #0a0a18;
        border: 1px solid rgba(255,46,151,.35); color: #b6ffd0; white-space: pre-wrap; }
  .meta { font-size: 12px; color: #5f7f9a; }
  .flag { color: #ff2e97; }
  footer { margin-top: 26px; font-size: 12px; color: #5f7f9a; }
  @media (max-width: 420px) { body { padding: 20px 16px; } }
</style>
</head>
<body>
<header>
  <div class="sub">World Of B0t // challenge 06</div>
  <h1>COMMAND DECK</h1>
  <div class="bar"></div>
  <div class="meta">packet console v<?= LAB_VERSION ?> &mdash; internal operations deck</div>
</header>

<main>
  <div class="card">
    <h2>Probe target</h2>
    <form method="post" action="/">
      <div class="row">
        <div>
          <label for="host">host</label>
          <input type="text" id="host" name="host" value="<?= $host_attr ?>" placeholder="127.0.0.1" autocomplete="off">
        </div>
        <div>
          <label for="count">packet count</label>
          <input type="text" id="count" name="count" value="<?= $count_attr ?>" autocomplete="off">
        </div>
      </div>
      <div class="tools">
        <button type="submit" name="tool" value="ping">PING</button>
        <button type="submit" name="tool" value="traceroute" class="alt">TRACEROUTE</button>
      </div>
    </form>
  </div>

  <?php if ($out_html !== ''): ?>
  <div class="card">
    <h2>deck output &mdash; <?= htmlspecialchars($tool, ENT_QUOTES) ?></h2>
    <pre><?= $out_html ?></pre>
  </div>
  <?php endif; ?>

  <div class="card">
    <h2>deck notes</h2>
    <p class="meta">
      The console shells out to the host tools and echoes the raw output.
      The tool name is whitelisted. The host is quoted. The packet count is a
      number, so it is pasted in as typed.
    </p>
    <p class="meta">
      deck env wired: <span class="flag"><?= getenv('W0B_FLAG') === false || getenv('W0B_FLAG') === '' ? 'no' : 'yes' ?></span>
    </p>
  </div>
</main>

<footer>
  deck &copy; 20XX &mdash; <span class="flag">unauthorised access is logged</span>
</footer>
</body>
</html>
