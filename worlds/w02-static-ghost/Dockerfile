FROM nginx:alpine

# Static site lives in html/; nginx.conf replaces the default server block.
COPY nginx.conf /etc/nginx/nginx.conf
COPY html/ /usr/share/nginx/html/

# Flag is injected at runtime as an env var; never baked into a layer.
# /docker-entrypoint.d runs these scripts before nginx starts.
COPY docker/40-inject-flag.sh /docker-entrypoint.d/40-inject-flag.sh
RUN chmod +x /docker-entrypoint.d/40-inject-flag.sh

ENV W0B_FLAG=""
EXPOSE 80
