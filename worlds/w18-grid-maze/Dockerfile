FROM python:3.12-alpine

# GRID MAZE :: session mint (World Of B0t challenge 18)
# Category: Web | Difficulty: medium | Vuln: predictable session id + role bleed

WORKDIR /app
COPY app/server.py /app/server.py

# Injected at runtime by the launcher. Empty here on purpose so nothing is
# baked into an image layer.
ENV W0B_FLAG=""
ENV PORT=8080

# No third-party packages: stdlib only by design.
RUN W0B_SELFCHECK=1 python3 server.py

EXPOSE 8080
USER 10001
CMD ["python3", "server.py"]
