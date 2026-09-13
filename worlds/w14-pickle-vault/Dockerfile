FROM python:3.12-alpine

# PICKLE VAULT :: session store (World Of B0t challenge 14)
# Category: Pwn | Difficulty: medium | Vuln: unguarded pickle.loads on a cookie

WORKDIR /app
COPY app/vault.py app/server.py app/entrypoint.py /app/

# Injected at runtime by the launcher. Empty here on purpose so nothing is
# baked into an image layer.
ENV W0B_FLAG=""
ENV PORT=8080

# The flag module is root-owned and mode 0400: only root can read it. The server
# reads it ONCE at boot while still root, then drops to uid 10001 for the whole
# request-serving lifetime (see entrypoint.sh). So the running service can never
# `cat` the file - reading it is not a path. Executing code inside the process
# that already holds the value is the path, which is the point of the lab.
RUN chown 0:0 /app/vault.py && chmod 0400 /app/vault.py

# Import-time self-check: the benign session round-trips, and the hostile
# __reduce__ payload runs. If either breaks the lab is dead on arrival.
# The source stays a plain module and is imported by absolute path.
RUN cd /app && W0B_FLAG=hex4b0t{selfcheck} python3 -c "import server; server._self_check()"

EXPOSE 8080
# Boot is root (to read the 0400 vault), then entrypoint.py drops to uid 10001
# before a single request is served.
USER 0
CMD ["python3", "entrypoint.py"]
