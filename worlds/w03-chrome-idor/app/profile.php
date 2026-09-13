<?php
require __DIR__ . '/lib.php';
$me = w0b_current();
if (!$me) {
    header('Location: /index.php');
    exit;
}

// VULNERABLE: only checks that *a* session exists, never that the requested
// record belongs to it. Any authenticated user can read any id.
$id = (int)($_GET['id'] ?? $_GET['user_id'] ?? $me['id']);
$target = w0b_user($id);

echo w0b_head('CHROME IDOR :: profile');
?>
<h1>IDENTITY RECORD</h1>
<div class="sub">// viewing as <?= h($me['username']) ?> [<?= h($me['role']) ?>]</div>
<?php if (!$target): ?>
  <div class="err">NO RECORD FOR ID <?= h($id) ?>.</div>
<?php else: ?>
  <div class="row"><span class="k">ID</span><span class="v"><?= (int)$target['id'] ?></span></div>
  <div class="row"><span class="k">USERNAME</span><span class="v"><?= h($target['username']) ?></span></div>
  <div class="row"><span class="k">ROLE</span>
    <span class="v"><span class="role <?= $target['role'] === 'admin' ? 'admin' : '' ?>"><?= h($target['role']) ?></span></span></div>
  <div class="row"><span class="k">EMAIL</span><span class="v"><?= h($target['email']) ?></span></div>
  <div class="row"><span class="k">NOTE</span><span class="v"><?= h($target['note']) ?></span></div>
  <?php if ($target['role'] === 'admin'): ?>
    <div class="flag"><?= h($target['note']) ?></div>
  <?php endif; ?>
<?php endif; ?>
<div class="hint"><a href="/profile.php?id=<?= (int)$me['id'] ?>">my record</a> &middot; <a href="/logout.php">terminate session</a></div>
<?= w0b_foot() ?>
