FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY app/ /src
RUN CGO_ENABLED=0 go build -o /ghost-shell .

FROM alpine:3.20

# psql is how the console reaches the datastore - no Go driver, no cgo.
RUN apk add --no-cache postgresql16-client

COPY --from=builder /ghost-shell /usr/local/bin/ghost-shell

# Flag is injected at runtime as an env var; never baked into a layer.
# It lives in THIS container's environment, so the chain has to end in code
# execution here - reading the datastore alone does not produce it.
ENV W0B_FLAG=""

USER 10001
EXPOSE 8080
CMD ["/usr/local/bin/ghost-shell"]
