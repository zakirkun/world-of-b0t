FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY app/ /src
RUN CGO_ENABLED=0 go build -o /concat-walk .

FROM alpine:3.20

# Seed script drops the public files and writes the flag one level ABOVE the
# served root, so it is only readable by traversing out of it.
COPY docker/10-seed.sh /usr/local/bin/10-seed.sh
RUN chmod +x /usr/local/bin/10-seed.sh

COPY --from=builder /concat-walk /usr/local/bin/concat-walk

# Flag is injected at runtime as an env var; never baked into a layer.
ENV W0B_FLAG=""

EXPOSE 8080
CMD ["/bin/sh", "-c", "/usr/local/bin/10-seed.sh && exec /usr/local/bin/concat-walk"]
