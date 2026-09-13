FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY proxy/ /src
RUN CGO_ENABLED=0 go build -o /edge-shift .

FROM alpine:3.20
RUN adduser -D -u 10001 edge
COPY --from=builder /edge-shift /usr/local/bin/edge-shift

# Flag is injected at runtime as an env var; never baked into a layer.
# (The gateway never reads it - it only needs to be able to REACH the origin.)
ENV W0B_FLAG=""
USER edge
EXPOSE 8080
CMD ["/usr/local/bin/edge-shift"]
