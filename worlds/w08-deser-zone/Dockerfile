FROM python:3.12-alpine

# DESER ZONE :: profile store (World Of B0t challenge 08)
# Category: Pwn | Difficulty: hard | Vuln: insecure deserialization
#   (json.loads object_hook eval + constructor call - NOT pickle)

WORKDIR /app
COPY app/server.py /app/server.py

# Flag is injected at runtime as an env var; never baked into a layer.
ENV W0B_FLAG=""
ENV PORT=8080

# No third-party packages: stdlib only by design.
RUN W0B_SELFCHECK=1 W0B_FLAG='hex4b0t{selfcheck}' python3 server.py

EXPOSE 8080
USER 10001
CMD ["python3", "server.py"]
