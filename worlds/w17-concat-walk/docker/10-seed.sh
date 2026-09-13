#!/bin/sh
# w17 :: seed the drop volume and place the flag OUTSIDE the served root.
# Only reachable by walking out of /srv/files with a leading "../".
set -e

mkdir -p /srv/files /srv/private

if [ -z "$W0B_FLAG" ]; then
    echo "w17: W0B_FLAG not set, writing placeholder" >&2
    FLAG="hex4b0t{REPLACED_AT_RUNTIME}"
else
    FLAG="$W0B_FLAG"
fi

printf '%s\n' "$FLAG" > /srv/private/flag.txt
chmod 600 /srv/private/flag.txt

# Public drop contents. These are the only files the app is meant to serve.
cat > /srv/files/manifest.txt <<'EOF'
CONCAT WALK :: public drop
  manifest.txt   this file
  relay.log      noisy relay chatter
  keys.txt       decommissioned key fingerprints (public)
EOF

printf 'relay ok seq=%s\n' "$(date +%s)" > /srv/files/relay.log
printf 'a1:ff:09:de:00:17   retired\nb2:41:7c:11:00:17   retired\n' > /srv/files/keys.txt

echo "w17: drop seeded; flag at /srv/private/flag.txt"
