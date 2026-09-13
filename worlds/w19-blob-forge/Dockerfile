FROM php:8.3-apache

# BLOB FORGE :: front controller (World Of B0t challenge 19)
# Category: Web | Difficulty: medium | Vuln: PHP object injection -> arbitrary file write

# Injected at runtime by the launcher. Empty here on purpose so nothing is
# baked into an image layer. NOTE: php:8.3-apache does *not* set ClearEnv, and
# getenv() in the mod_php worker DOES see this variable (verified). $_SERVER
# does not (that superglobal is CLI-only) and /proc/self/environ is unreadable,
# so config.php reads the flag with getenv().
ENV W0B_FLAG=""

COPY app/ /var/www/html/

# The /api/* routes are extensionless paths that all land on index.php. Other
# paths (e.g. a dropped /shell.php) are real files and must bypass the rewrite.
RUN a2enmod rewrite \
 && printf '<Directory /var/www/html>\n  AllowOverride All\n</Directory>\n' \
      > /etc/apache2/conf-available/w19-router.conf \
 && a2enconf w19-router

# The web user must be able to write inside the document root -- that is the
# whole point of the challenge (the cache lands next to the app and is served).
RUN chown -R www-data:www-data /var/www/html \
 && chmod 775 /var/www/html

EXPOSE 80
