FROM php:8.3.36-fpm-alpine3.24@sha256:81cb692948e6de4275f7e107c50a34e963a440660f2c5b8502d11071f7d30338 AS source

ARG LIMESURVEY_VERSION=7.7.0+261020
ARG LIMESURVEY_ARCHIVE_SHA256=925dd275e301b3a12fd18e14994bd21cbee34a08202bc618278c3c1cfc16988d

WORKDIR /var/www/html

RUN set -eux; \
    apk add --no-cache unzip; \
    archive=/tmp/limesurvey.zip; \
    curl --fail --location --retry 3 --retry-all-errors \
        --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 180 \
        "https://download.limesurvey.org/latest-master/limesurvey${LIMESURVEY_VERSION}.zip" \
        --output "${archive}"; \
    archive_sha256="$(sha256sum "${archive}")"; \
    test "${archive_sha256%% *}" = "${LIMESURVEY_ARCHIVE_SHA256}"; \
    unzip -Z1 "${archive}" > /tmp/limesurvey-members; \
    awk 'BEGIN { count = 0 } /^\// || /(^|\/)\.\.(\/|$)/ || !/^limesurvey\// { exit 1 } { count++ } END { if (!count) exit 1 }' /tmp/limesurvey-members; \
    rm -f /tmp/limesurvey-members; \
    unzip -q "${archive}" -d /tmp/limesurvey-source; \
    cp -a /tmp/limesurvey-source/limesurvey/. /var/www/html/; \
    rm -rf /tmp/limesurvey-source; \
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

FROM php:8.3.36-fpm-alpine3.24@sha256:81cb692948e6de4275f7e107c50a34e963a440660f2c5b8502d11071f7d30338 AS runtime

ARG LIMESURVEY_VERSION=7.7.0+261020
ARG LIMESURVEY_ARCHIVE_SHA256=925dd275e301b3a12fd18e14994bd21cbee34a08202bc618278c3c1cfc16988d
ARG WRAPPER_COMMIT=development

LABEL org.opencontainers.image.title="LimeSurvey for Coolify" \
      org.opencontainers.image.description="Pinned LimeSurvey Community Edition PHP-FPM runtime" \
      org.opencontainers.image.source="https://github.com/cahangeorge/LimeSurvey" \
      org.opencontainers.image.version="7.7.0+261020" \
      org.opencontainers.image.revision="${WRAPPER_COMMIT}" \
      io.omnestack.limesurvey.upstream-source-type="release-zip" \
      io.omnestack.limesurvey.upstream-sha256="${LIMESURVEY_ARCHIVE_SHA256}" \
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
