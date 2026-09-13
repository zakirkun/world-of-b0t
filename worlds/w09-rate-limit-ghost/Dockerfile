FROM python:3.12-alpine

# RATE LIMIT GHOST :: distributed request throttle (World Of B0t challenge 09)
# Category: DevOpsSec | Difficulty: hard | Vuln: Race condition / limit bypass

WORKDIR /app
COPY app/server.py /app/server.py

# Flag is injected at runtime as an env var; never baked into a layer.
ENV W0B_FLAG=""
ENV PORT=8080
ENV REDIS_HOST=redis
ENV REDIS_PORT=6379

# The app is the only thing that needs Redis; the limiter is the bug, and it
# must not move into the image build.
RUN pip install --no-cache-dir flask redis

# ponytail: an import check is the whole build self-test; the real check is
# solution/probe.sh against a running stack.
RUN python3 -c "import flask, redis; print('deps ok', flask.__version__)"

EXPOSE 8080
USER 10001
CMD ["python3", "server.py"]
