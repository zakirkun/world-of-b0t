FROM python:3.12-alpine

# DOSSIER TRACE :: OSINT trail lab (World Of B0t challenge 23)
# Category: OSINT | Difficulty: medium
# Vuln: decommissioned portal leaves internal artifacts exposed

WORKDIR /app
COPY app/server.py /app/server.py

# Flag is injected at runtime as an env var; never baked into a layer.
ENV W0B_FLAG=""
ENV PORT=8080

# ponytail: import check is the whole build self-test; the real check is
# solution/probe.sh against the running container.
RUN python3 -c "import server; print('import ok')"

EXPOSE 8080
USER 10001
CMD ["python3", "server.py"]
