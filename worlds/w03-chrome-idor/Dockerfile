FROM php:8.3-apache

COPY app/ /var/www/html/

# Flag is injected at runtime as an env var; never baked into a layer.
ENV W0B_FLAG=""
EXPOSE 80
