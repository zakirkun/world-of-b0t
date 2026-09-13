FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY app/ /src
RUN CGO_ENABLED=0 go build -o /gate-scan .

FROM alpine:3.20
RUN adduser -D -u 10001 scan
COPY --from=builder /gate-scan /usr/local/bin/gate-scan

# Flag is injected at runtime as an env var; never baked into a layer.
# (The prober never reads it - it only needs to be able to REACH the farm.)
ENV W0B_FLAG=""
USER scan
EXPOSE 8080
CMD ["/usr/local/bin/gate-scan"]
