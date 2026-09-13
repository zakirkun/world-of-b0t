<?php
require __DIR__ . '/lib.php';
w0b_session_start();

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = (string)($_POST['username'] ?? '');
    $p = (string)($_POST['password'] ?? '');

    // ponytail: plaintext compare, lab only.
    foreach (w0b_users() as $user) {
        if ($user['username'] === $u && $user['password'] === $p) {
            session_regenerate_id(true);
            $_SESSION['uid'] = $user['id'];
            header('Location: /profile.php?id=' . $user['id']);
            exit;
        }
    }
    $error = 'ACCESS DENIED.';
}

$me = w0b_current();
echo w0b_head('CHROME IDOR :: login');
?>
<h1>CHROME IDOR</h1>
<div class="sub">// identity vault :: world of b0t :: w03</div>
<?php if ($me): ?>
  <div class="row"><span class="k">SESSION</span>
    <span class="v"><?= h($me['username']) ?> &mdash; <a href="/profile.php?id=<?= (int)$me['id'] ?>">profile</a></span></div>
  <div class="hint"><a href="/logout.php">terminate session</a></div>
<?php else: ?>
  <form method="post">
    <label>OPERATOR</label>
    <input name="username" autocomplete="off" spellcheck="false" autofocus>
    <label>PASSKEY</label>
    <input name="password" type="password" autocomplete="off">
    <button type="submit">AUTHENTICATE</button>
  </form>
  <?php if ($error): ?><div class="err"><?= h($error) ?></div><?php endif; ?>
  <div class="hint">
    Compromised credential from the last breach:<br>
    <code>k4i / chromes4life</code><br>
    Records are keyed by numeric identity. So is <code>/profile.php</code>.
  </div>
<?php endif; ?>
<?= w0b_foot() ?>
