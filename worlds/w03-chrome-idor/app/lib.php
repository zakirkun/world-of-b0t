<?php
// CHROME IDOR :: identity vault :: world of b0t challenge 03
// Users live in a static array, so the only flaw here is missing authorization.

function w0b_users(): array {
    static $users = null;
    if ($users !== null) return $users;

    $flag = getenv('W0B_FLAG') ?: 'hex4b0t{missing_flag}';

    // ponytail: plain passwords, it's a lab. Hash if this ever ships.
    $users = [
        1001 => [
            'id'       => 1001,
            'username' => 'k4i',
            'password' => 'chromes4life',
            'role'     => 'user',
            'email'    => 'k4i@neon.vault',
            'note'     => 'Standard operator. Nothing to see here.',
        ],
        1002 => [
            'id'       => 1002,
            'username' => 'r3iko',
            'password' => 'sunset_blade',
            'role'     => 'user',
            'email'    => 'r3iko@neon.vault',
            'note'     => 'Runner. Delivers packages, asks no questions.',
        ],
        9001 => [
            'id'       => 9001,
            'username' => 'admin',
            'password' => 'N3on_Gr1d_Adm1n!',
            'role'     => 'admin',
            'email'    => 'root@neon.vault',
            'note'     => $flag,
        ],
    ];
    return $users;
}

function w0b_user(int $id): ?array {
    return w0b_users()[$id] ?? null;
}

function w0b_session_start(): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

function w0b_current(): ?array {
    w0b_session_start();
    $id = $_SESSION['uid'] ?? null;
    return is_int($id) ? w0b_user($id) : null;
}

function w0b_head(string $title): string {
    return <<<HTML
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="lab" content="w03">
<title>{$title}</title>
<style>
 body{margin:0;min-height:100vh;display:grid;place-items:center;background:#05050c;
   color:#cfefff;font:14px/1.5 "SF Mono",Consolas,monospace}
 .box{width:min(560px,92vw);padding:34px;border:1px solid #10384a;border-radius:14px;
   background:linear-gradient(180deg,#0a0a16,#07070f);
   box-shadow:0 0 40px rgba(0,240,255,.12),inset 0 0 60px rgba(0,240,255,.03)}
 h1{margin:0 0 4px;font-size:24px;letter-spacing:4px;color:#00f0ff;
   text-shadow:0 0 12px rgba(0,240,255,.7)}
 .sub{color:#5d7285;font-size:11px;letter-spacing:2px;margin-bottom:22px}
 label{display:block;font-size:11px;letter-spacing:1.5px;color:#5d7285;margin:14px 0 6px}
 input{width:100%;padding:11px 12px;border-radius:6px;background:#050510;color:#cfefff;
   border:1px solid #16324a;box-sizing:border-box}
 input:focus{outline:none;border-color:#00f0ff;box-shadow:0 0 0 3px rgba(0,240,255,.12)}
 button{width:100%;margin-top:20px;padding:12px;border-radius:6px;cursor:pointer;
   background:rgba(0,240,255,.1);border:1px solid #00f0ff;color:#00f0ff;
   letter-spacing:2px;font:inherit}
 button:hover{background:rgba(0,240,255,.2);box-shadow:0 0 18px rgba(0,240,255,.4)}
 .err{margin-top:16px;color:#ff2e97;font-size:12px;white-space:pre-wrap}
 .hint{margin-top:22px;color:#3d4d5c;font-size:11px;line-height:1.7}
 .row{display:flex;justify-content:space-between;gap:16px;padding:9px 0;
   border-bottom:1px solid #12202e;font-size:13px}
 .k{color:#5d7285;font-size:11px;letter-spacing:1.5px}
 .v{color:#cfefff;text-align:right;word-break:break-all}
 .role{display:inline-block;padding:2px 8px;border-radius:99px;font-size:10px;
   letter-spacing:2px;border:1px solid #ff2e97;color:#ff2e97}
 .role.admin{border-color:#39ff88;color:#39ff88}
 code{color:#ffe600}
 .flag{margin-top:18px;padding:14px;border:1px dashed #39ff88;border-radius:8px;
   color:#39ff88;word-break:break-all;background:rgba(57,255,136,.05)}
 a{color:#00f0ff}
</style></head><body><div class="box">
HTML;
}

function w0b_foot(): string {
    return "</div></body></html>";
}

function h($s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}
