FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY relay/ /src
RUN CGO_ENABLED=0 go build -o /relay-veil .

FROM alpine:3.20
RUN adduser -D -u 10001 relay
COPY --from=builder /relay-veil /usr/local/bin/relay-veil

# Route tables ship with the image. conf.d/ is the loadable set and public.conf
# is the only one loaded at boot. The management route table lives outside that
# directory, in private/, which the boot scan never reads.
COPY conf.d/ /srv/relay/conf.d/
COPY private/ /srv/relay/private/

# Flag is injected at runtime as an env var; never baked into a layer.
# (The relay never reads it - it only needs to be able to REACH the upstream.)
ENV W0B_FLAG=""
USER relay
EXPOSE 8080
CMD ["/usr/local/bin/relay-veil"]
