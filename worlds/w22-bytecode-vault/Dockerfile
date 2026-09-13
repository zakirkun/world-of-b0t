FROM python:3.12-alpine

# BYTECODE VAULT :: sealed module (World Of B0t challenge 22)
# Category: Graybox | Difficulty: hard | Vuln: secret logic recoverable from shipped bytecode

WORKDIR /app
COPY app/ /app/

# Compile the sealed module and ship ONLY the bytecode. vault.py is deleted so
# no source reaches the final image; the bare top-level vault.pyc is verified
# importable by a plain `import vault` on python:3.12 (see server.py).
RUN cd /app && python3 -m py_compile vault.py \
    && mv __pycache__/vault.cpython-312.pyc /app/vault.pyc \
    && rm -rf __pycache__ vault.py \
    && python3 -c "import sys; sys.path.insert(0,'/app'); import vault; print('bytecode import ok')"

# Injected at runtime by the launcher. Empty here on purpose so nothing is
# baked into an image layer. Flag is injected at runtime as an env var; never
# baked into a layer.
ENV W0B_FLAG=""
ENV PORT=8080

# Build-time proof the lab is solvable from the artifact alone.
RUN W0B_SELFCHECK=1 python3 server.py

EXPOSE 8080
USER 10001
CMD ["python3", "server.py"]
