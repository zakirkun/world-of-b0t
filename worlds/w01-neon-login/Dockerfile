FROM python:3.12-alpine

WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3

COPY app/ /app/

# Flag is injected at runtime as an env var; never baked into a layer.
ENV W0B_FLAG=""
EXPOSE 5000
CMD ["python", "server.py"]
