FROM python:3.12-alpine

# RATE GAUNTLET :: coupon redemption desk (World Of B0t challenge 15)
# Category: DevOpsSec | Difficulty: easy | Vuln: TOCTOU race on a redemption limit

WORKDIR /app
COPY app/server.py /app/

# Injected at runtime by the launcher. Empty here on purpose so nothing is
# baked into an image layer.
ENV W0B_FLAG=""
ENV PORT=8080

# No third-party packages and no build step: http.server + sqlite3 are stdlib.
# ponytail: a syntax/import check is the whole self-test; the real check is
# solution/probe.sh against a running container.
RUN python3 -c "import ast,pathlib; ast.parse(pathlib.Path('server.py').read_text())"

EXPOSE 8080
USER 10001
CMD ["python3", "server.py"]
