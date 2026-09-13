FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY . /src
RUN CGO_ENABLED=0 go build -o /token-crypt .

FROM alpine:3.20
RUN adduser -D -u 10001 crypt
COPY --from=builder /token-crypt /usr/local/bin/token-crypt

# Flag is injected at runtime as an env var; never baked into a layer.
ENV W0B_FLAG=""
USER crypt
EXPOSE 8080
CMD ["/usr/local/bin/token-crypt"]
