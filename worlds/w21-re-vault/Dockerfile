FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY app/ /src
# -w drops DWARF debug info; -s would also drop the symbol table. We keep the
# symbols so `go tool objdump -s 'main\.'` works on the shipped binary - the
# challenge is recovering the derivation, not fighting symbol stripping.
RUN CGO_ENABLED=0 go build -ldflags="-w" -o /re-vault .

FROM alpine:3.20
RUN adduser -D -u 10001 vault
COPY --from=builder /re-vault /usr/local/bin/re-vault

# Flag is injected at runtime as an env var; never baked into a layer.
ENV W0B_FLAG=""
USER 10001
EXPOSE 8080
CMD ["/usr/local/bin/re-vault"]
