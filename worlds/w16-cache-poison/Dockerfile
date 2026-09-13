FROM python:3.12-alpine

# CACHE POISON :: cache-aware preview node (World Of B0t challenge 16)
# Category: Web | Difficulty: easy | Vuln: CRLF injection into a response header

WORKDIR /app
COPY app/server.py /app/

# Injected at runtime by the launcher. Empty here on purpose so nothing is
# baked into an image layer.
ENV W0B_FLAG=""
ENV PORT=8080

# No third-party packages: stdlib only by design.
RUN python3 -c "import ast; ast.parse(open('server.py').read())"

EXPOSE 8080
USER 10001
CMD ["python3", "server.py"]
