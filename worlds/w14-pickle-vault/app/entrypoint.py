"""PICKLE VAULT :: boot as root, read the vault, drop privileges, serve.

vault.py is root-owned and 0400, so this import only succeeds while we are still
root. Once the value is in memory we irreversibly drop to uid 10001 and exec the
server. From that point on the file is unreadable to this process, but the flag
is already imported - which is exactly the property the lab turns on: reading the
file is not a path, running code inside the process is.
"""

import os

# Import while still root. This is the only moment the secret can be read.
import server  # noqa: F401  (imports vault -> VAULT_FLAG, and self-checks)

UID = 10001

# Drop privileges for good. setuid is irreversible for the process.
os.setgroups([])
os.setgid(UID)
os.setuid(UID)

assert os.getuid() == UID, os.getuid()

server.main()
