FROM php:8.3-apache

# COMMAND DECK :: packet console (World Of B0t challenge 06)
# Category: Web | Difficulty: medium | Vuln: Command injection

# Flag is injected at runtime as an env var; never baked into a layer.
# php:8.3-apache keeps the exported Docker ENV visible to the mod_php worker, so
# getenv('W0B_FLAG') reads it (verified). $_SERVER does not under mod_php.
ENV W0B_FLAG=""

# The deck shells out to these; the base image ships neither.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping traceroute \
 && rm -rf /var/lib/apt/lists/*

COPY app/ /var/www/html/

EXPOSE 80
