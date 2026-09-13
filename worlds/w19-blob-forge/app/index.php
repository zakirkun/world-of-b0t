<?php
// BLOB FORGE :: front controller.  Category: Web | Difficulty: medium
//
// Every request unpacks the caller's `prefs` cookie. The cookie is the caller's
// own data, so we hand it straight to the legacy serializer the shop has used
// since v1 -- see classes.php for the objects that can come back out of it.
require __DIR__ . '/classes.php';

const LAB_VERSION = '0.19.3';

$prefs   = null;   // decoded preference blob (array or object)
$prefsErr = null;  // why decoding failed, if it did
$route   = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

// ---------------------------------------------------------------------------
// decode the prefs blob
// ---------------------------------------------------------------------------
$raw = $_COOKIE['prefs'] ?? null;
if ($raw !== null) {
    $decoded = base64_decode($raw, true);
    if ($decoded === false) {
        $prefsErr = 'prefs: not valid base64';
    } else {
        $prefs = @unserialize($decoded);
        if ($prefs === false && $decoded !== serialize(false)) {
            $prefsErr = 'prefs: could not be unpacked';
        }
    }
}

// ---------------------------------------------------------------------------
// routes
// ---------------------------------------------------------------------------

// healthcheck -- no secrets here, just enough to script against.
if ($route === '/api/health') {
    header('content-type: application/json');
    echo json_encode([
        'service'    => 'blob-forge',
        'lab'        => 'w19',
        'version'    => LAB_VERSION,
        'php'        => PHP_VERSION,
        'serializer' => 'php-serialize',
    ]);
    exit;
}

// the reflection endpoint: hand back what we decoded from your cookie.
if ($route === '/api/prefs') {
    header('content-type: application/json');
    if ($raw === null) {
        echo json_encode(['error' => 'no prefs cookie set'], JSON_UNESCAPED_SLASHES);
        exit;
    }
    if ($prefsErr !== null) {
        echo json_encode(['error' => $prefsErr, 'raw_len' => strlen($raw)], JSON_UNESCAPED_SLASHES);
        exit;
    }
    echo json_encode([
        'decoded' => $prefs,
        'type'    => is_object($prefs) ? get_class($prefs) : gettype($prefs),
        'fields'  => is_object($prefs) ? get_object_vars($prefs) : null,
    ], JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
    exit;
}

// ---------------------------------------------------------------------------
// landing page
// ---------------------------------------------------------------------------
$prefsJson = $prefs === null
    ? 'null'
    : json_encode($prefs, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="lab" content="w19">
<title>BLOB FORGE // w19</title>
<style>
  :root { --bg:#05050c; --cy:#00f0ff; --pk:#ff2e97; --dim:#5a6a8a; --fg:#c8d6f0; }
  * { box-sizing:border-box; }
  body {
    margin:0; padding:32px 20px 64px; background:var(--bg); color:var(--fg);
    font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    background-image:radial-gradient(circle at 15% 0%,rgba(0,240,255,.09),transparent 45%),
                     radial-gradient(circle at 85% 10%,rgba(255,46,151,.08),transparent 45%);
    min-height:100vh;
  }
  .wrap { max-width:820px; margin:0 auto; }
  h1 { font-size:26px; margin:0 0 4px; letter-spacing:.14em; color:var(--cy);
       text-shadow:0 0 14px rgba(0,240,255,.45); }
  h1 span { color:var(--pk); text-shadow:0 0 14px rgba(255,46,151,.45); }
  .sub { color:var(--dim); letter-spacing:.22em; font-size:11px; text-transform:uppercase; margin-bottom:28px; }
  .card { border:1px solid rgba(0,240,255,.22); background:rgba(0,240,255,.03);
          padding:18px 20px; margin:0 0 18px; border-radius:4px; }
  .card h2 { font-size:11px; letter-spacing:.22em; text-transform:uppercase;
             color:var(--pk); margin:0 0 10px; }
  code, pre { color:var(--cy); }
  pre { background:#02020a; border:1px solid rgba(0,240,255,.16); padding:12px 14px;
        border-radius:3px; overflow-x:auto; margin:8px 0 0; font-size:13px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  td { padding:6px 0; border-bottom:1px dashed rgba(0,240,255,.12); vertical-align:top; }
  td:first-child { color:var(--dim); width:130px; white-space:nowrap; }
  a { color:var(--cy); }
  .err { color:var(--pk); }
  footer { color:var(--dim); font-size:11px; letter-spacing:.16em; margin-top:34px;
           border-top:1px solid rgba(0,240,255,.14); padding-top:14px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>BLOB <span>FORGE</span></h1>
  <div class="sub">preference cache &middot; w19 &middot; v<?= LAB_VERSION ?></div>

  <div class="card">
    <h2>Service</h2>
    <table>
      <tr><td>decode endpoint</td><td><a href="/api/prefs">GET /api/prefs</a></td></tr>
      <tr><td>health</td><td><a href="/api/health">GET /api/health</a></td></tr>
      <tr><td>cookie</td><td><code>prefs</code> &mdash; base64 of a serialized blob</td></tr>
      <tr><td>serializer</td><td><code>php-serialize</code> (legacy, kept for old backups)</td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Your blob</h2>
<?php if ($raw === null): ?>
    <p>No <code>prefs</code> cookie on this request. Set one and reload:
    <code>curl -b 'prefs=&lt;base64&gt;' <?= htmlspecialchars($route) ?></code></p>
<?php elseif ($prefsErr !== null): ?>
    <p class="err"><?= htmlspecialchars($prefsErr) ?></p>
<?php else: ?>
    <p>Decoded <code><?= htmlspecialchars(is_object($prefs) ? get_class($prefs) : gettype($prefs)) ?></code>:</p>
    <pre><?= htmlspecialchars((string) $prefsJson) ?></pre>
<?php endif; ?>
  </div>

  <div class="card">
    <h2>Cache behaviour</h2>
    <p>The shop's <code>PreferenceCache</code> object persists itself when the
    request ends. A blob with an empty <code>content</code>, or a <code>ttl</code>
    of <code>0</code>, is a no-op &mdash; those are the purge sentinels.</p>
  </div>

  <footer>WORLD OF B0T // challenge 19 // authorized testing only</footer>
</div>
</body>
</html>
