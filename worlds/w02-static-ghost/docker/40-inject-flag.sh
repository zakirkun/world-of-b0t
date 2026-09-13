#!/bin/sh
# w02 :: inject the runtime flag into the webroot.
# The filename is the token leaked in /backup/app.py.bak, so the flag is only
# reachable at the path the player derives from the leaked source.
set -e

TOKEN="sg_vault_9f3a1c0d"
WEBROOT="/usr/share/nginx/html"
OUT="$WEBROOT/backup/vault/$TOKEN.txt"

if [ -z "$W0B_FLAG" ]; then
    echo "w02: W0B_FLAG not set, writing placeholder" >&2
    FLAG="hex4b0t{REPLACED_AT_RUNTIME}"
else
    FLAG="$W0B_FLAG"
fi

mkdir -p "$WEBROOT/backup/vault"
printf '%s\n' "$FLAG" > "$OUT"
chmod 644 "$OUT"
echo "w02: flag injected at /backup/vault/$TOKEN.txt"
