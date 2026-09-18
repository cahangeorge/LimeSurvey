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

managed_plugin_source=/opt/limesurvey-managed-plugins/ResendEmail
managed_plugin_target=/var/www/html/plugins/ResendEmail
managed_plugin_staging=/var/www/html/plugins/.ResendEmail.staging.$$

if [ -d "$managed_plugin_source" ]; then
    rm -rf "$managed_plugin_staging"
    cp -R "$managed_plugin_source" "$managed_plugin_staging"
    if [ "$(id -u)" -eq 0 ]; then
        chown -R www-data:www-data "$managed_plugin_staging"
    fi
    rm -rf "$managed_plugin_target"
    mv "$managed_plugin_staging" "$managed_plugin_target"
fi

exec "$@"
