FROM php:8.3.35-fpm-alpine3.24@sha256:454b11c8907e32878ce92e87b13c14e1bbe6e1b10f4f96d4a19c9b62ec675d41 AS source

ARG LIMESURVEY_COMMIT=6c2ae12f8a2245fbc0eb4ea0a677155d1ec9b7d9
ARG LIMESURVEY_ARCHIVE_SHA256=0cc0378756d14c2c8f9634b4f352fe490d167695b24673e38b1b4f321d359bc5

WORKDIR /var/www/html

RUN set -eux; \
    archive=/tmp/limesurvey.tar.gz; \
    curl --fail --location --retry 3 --retry-all-errors \
        --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 180 \
        "https://github.com/LimeSurvey/LimeSurvey/archive/${LIMESURVEY_COMMIT}.tar.gz" \
        --output "${archive}"; \
    archive_sha256="$(sha256sum "${archive}")"; \
    test "${archive_sha256%% *}" = "${LIMESURVEY_ARCHIVE_SHA256}"; \
    tar --extract --gzip --file "${archive}" --strip-components=1 --no-same-owner; \
    rm -f "${archive}"; \
    install -d -o www-data -g www-data application/config upload tmp plugins themes; \
    chown -R www-data:www-data application/config upload tmp plugins themes

# Composer's PHP inventory is authoritative; Trivy 0.75 reads installed.json.
# Add only scanner metadata for installed packages; do not resolve/update dependencies.
RUN php <<'PHP'
<?php
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator('/var/www/html', FilesystemIterator::SKIP_DOTS));
$count = 0;
foreach ($iterator as $file) {
    if ($file->getFilename() !== 'installed.php' || basename($file->getPath()) !== 'composer') {
        continue;
    }
    $data = require $file->getPathname();
    if (!isset($data['versions'], $data['root'])) {
        throw new RuntimeException('Unsupported Composer inventory');
    }
    $packages = [];
    foreach ($data['versions'] as $name => $package) {
        if ($name === ($data['root']['name'] ?? '__root__')) {
            continue;
        }
        if (!isset($package['install_path']) && (isset($package['provided']) || isset($package['replaced']))) {
            continue;
        }
        // Older Composer inventories omit install_path; require the physical vendor/name directory.
        $path = $package['install_path'] ?? ($file->getPath() . '/../' . $name);
        if (!is_dir($path) || empty($package['pretty_version'])) {
            throw new RuntimeException('Incomplete installed package');
        }
        $packages[] = ['name' => $name, 'version' => $package['pretty_version']];
    }
    if (!$packages) {
        throw new RuntimeException('Empty Composer inventory');
    }
    $encoded = json_encode(['packages' => $packages, 'dev' => false, 'dev-package-names' => []], JSON_THROW_ON_ERROR);
    if (file_put_contents($file->getPath() . '/installed.json', $encoded) === false) {
        throw new RuntimeException('Cannot write scanner inventory');
    }
    $count++;
}
if ($count < 2) {
    throw new RuntimeException('Missing upstream Composer inventories');
}
PHP

FROM php:8.3.35-fpm-alpine3.24@sha256:454b11c8907e32878ce92e87b13c14e1bbe6e1b10f4f96d4a19c9b62ec675d41 AS runtime

ARG LIMESURVEY_COMMIT=6c2ae12f8a2245fbc0eb4ea0a677155d1ec9b7d9
ARG LIMESURVEY_ARCHIVE_SHA256=0cc0378756d14c2c8f9634b4f352fe490d167695b24673e38b1b4f321d359bc5
ARG WRAPPER_COMMIT=development

LABEL org.opencontainers.image.title="LimeSurvey for Coolify" \
      org.opencontainers.image.description="Pinned LimeSurvey Community Edition PHP-FPM runtime" \
      org.opencontainers.image.source="https://github.com/cahangeorge/LimeSurvey" \
      org.opencontainers.image.version="7.1.1+260914" \
      org.opencontainers.image.revision="${WRAPPER_COMMIT}" \
      io.omnestack.limesurvey.upstream-revision="${LIMESURVEY_COMMIT}" \
      org.opencontainers.image.licenses="GPL-2.0-or-later"

# Kerberos/GSSAPI is outside this Resend-based MVP; Alpine c-client provides SSL.
RUN set -eux; \
    apk upgrade --no-cache; \
    apk add --no-cache ca-certificates curl c-client freetype libjpeg-turbo libpng \
        icu-libs icu-data-full oniguruma libldap libxml2 libzip libintl; \
    apk add --no-cache --virtual .build-deps $PHPIZE_DEPS pax-utils \
        curl-dev freetype-dev libjpeg-turbo-dev libpng-dev zlib-dev icu-dev \
        oniguruma-dev openldap-dev libxml2-dev libzip-dev gettext-dev \
        imap-dev openssl-dev; \
    docker-php-ext-configure gd --with-freetype --with-jpeg; \
    docker-php-ext-configure imap --with-imap-ssl; \
    docker-php-ext-configure ldap; \
    docker-php-ext-install -j"$(nproc)" bcmath curl exif gd gettext imap intl ldap \
        mbstring mysqli opcache pdo_mysql soap zip; \
    run_deps="$(scanelf --needed --nobanner --format '%n#p' --recursive \
        /usr/local/bin/php /usr/local/sbin/php-fpm /usr/local/lib/php/extensions \
        | tr ',' '\n' | sort -u \
        | awk 'system("[ -e /usr/local/lib/" $1 " ]") == 0 { next } { print "so:" $1 }')"; \
    apk add --no-cache --virtual .extension-rundeps $run_deps; \
    apk del --no-cache .build-deps; \
    php-fpm -t; \
    php -r 'foreach (["bcmath", "curl", "exif", "gd", "gettext", "imap", "intl", "ldap", "mbstring", "mysqli", "Zend OPcache", "pdo_mysql", "soap", "zip"] as $extension) { if (!extension_loaded($extension)) { fwrite(STDERR, "Missing PHP extension: {$extension}\n"); exit(1); } }'

WORKDIR /var/www/html

COPY --from=source --chown=root:root /var/www/html /var/www/html
RUN chown -R www-data:www-data application/config upload tmp plugins themes

COPY docker/php/php.ini /usr/local/etc/php/conf.d/zz-limesurvey-production.ini
COPY --chown=www-data:www-data plugins/ResendEmail /opt/limesurvey-managed-plugins/ResendEmail
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/limesurvey-entrypoint

EXPOSE 9000

STOPSIGNAL SIGQUIT

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD kill -0 1 && php-fpm -t || exit 1

ENTRYPOINT ["limesurvey-entrypoint"]
CMD ["php-fpm"]
