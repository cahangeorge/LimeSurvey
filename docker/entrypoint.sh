#!/bin/sh
set -eu

if [ "${1:-}" = "php-fpm" ]; then
    : "${DB_HOST:?DB_HOST is required}"
    : "${DB_NAME:?DB_NAME is required}"
    : "${DB_USER:?DB_USER is required}"
    : "${DB_PASSWORD:?DB_PASSWORD is required}"
fi

for directory in \
    /var/www/html/application/config \
    /var/www/html/upload \
    /var/www/html/tmp \
    /var/www/html/plugins \
    /var/www/html/themes
do
    install -d -o www-data -g www-data "$directory"
    if [ "$(id -u)" -eq 0 ]; then
        find "$directory" \( ! -user www-data -o ! -group www-data \) \
            -exec chown -h www-data:www-data {} +
    fi
done

exec "$@"
