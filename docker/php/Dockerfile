FROM php:8.3.33-fpm-bookworm@sha256:1547a7b6fc3509870fc732f73aebeee62e73af3365858b075d4aad78e983920f

ARG LIMESURVEY_COMMIT=6c2ae12f8a2245fbc0eb4ea0a677155d1ec9b7d9
ARG LIMESURVEY_ARCHIVE_SHA256=0cc0378756d14c2c8f9634b4f352fe490d167695b24673e38b1b4f321d359bc5

LABEL org.opencontainers.image.title="LimeSurvey for Coolify" \
      org.opencontainers.image.description="Pinned LimeSurvey Community Edition PHP-FPM runtime" \
      org.opencontainers.image.source="https://github.com/cahangeorge/LimeSurvey" \
      org.opencontainers.image.version="7.1.1+260914" \
      org.opencontainers.image.revision="${LIMESURVEY_COMMIT}" \
      org.opencontainers.image.licenses="GPL-2.0-or-later"

RUN set -eux; \
    saved_apt_mark="$(apt-mark showmanual)"; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libc-client2007e \
        libcurl4 \
        libfreetype6 \
        libicu72 \
        libjpeg62-turbo \
        libkrb5-3 \
        libldap-2.5-0 \
        libonig5 \
        libpng16-16 \
        libxml2 \
        libzip4 \
        libcurl4-openssl-dev \
        libfreetype6-dev \
        libicu-dev \
        libjpeg62-turbo-dev \
        libkrb5-dev \
        libldap2-dev \
        libonig-dev \
        libpng-dev \
        libxml2-dev \
        libzip-dev \
        libc-client2007e-dev \
        $PHPIZE_DEPS; \
    docker-php-ext-configure gd --with-freetype --with-jpeg; \
    docker-php-ext-configure imap --with-kerberos --with-imap-ssl; \
    docker-php-ext-configure ldap --with-libdir="lib/$(dpkg-architecture --query DEB_BUILD_MULTIARCH)"; \
    docker-php-ext-install -j"$(nproc)" \
        bcmath \
        curl \
        exif \
        gd \
        gettext \
        imap \
        intl \
        ldap \
        mbstring \
        mysqli \
        opcache \
        pdo_mysql \
        soap \
        zip; \
    apt-mark auto '.*' > /dev/null; \
    apt-mark manual ${saved_apt_mark} \
        ca-certificates \
        curl \
        libc-client2007e \
        libcurl4 \
        libfreetype6 \
        libicu72 \
        libjpeg62-turbo \
        libkrb5-3 \
        libldap-2.5-0 \
        libonig5 \
        libpng16-16 \
        libxml2 \
        libzip4; \
    find /usr/local/lib/php/extensions -type f -name '*.so' -exec ldd '{}' ';' \
        | awk '/=>/ { print $(NF - 1) }' \
        | sort -u \
        | xargs -r dpkg-query --search \
        | cut -d: -f1 \
        | sort -u \
        | xargs -r apt-mark manual; \
    apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
    rm -rf /var/lib/apt/lists/*; \
    php -r 'foreach (["bcmath", "curl", "exif", "gd", "gettext", "imap", "intl", "ldap", "mbstring", "mysqli", "Zend OPcache", "pdo_mysql", "soap", "zip"] as $extension) { if (!extension_loaded($extension)) { fwrite(STDERR, "Missing PHP extension: {$extension}\n"); exit(1); } }'

WORKDIR /var/www/html

RUN set -eux; \
    archive=/tmp/limesurvey.tar.gz; \
    curl --fail --location --retry 5 --retry-all-errors \
        "https://github.com/LimeSurvey/LimeSurvey/archive/${LIMESURVEY_COMMIT}.tar.gz" \
        --output "${archive}"; \
    echo "${LIMESURVEY_ARCHIVE_SHA256}  ${archive}" | sha256sum --check --strict; \
    tar --extract --gzip --file "${archive}" --strip-components=1 --no-same-owner; \
    rm -f "${archive}"; \
    install -d -o www-data -g www-data application/config upload tmp plugins themes; \
    chown -R www-data:www-data application/config upload tmp plugins themes

COPY docker/php/php.ini /usr/local/etc/php/conf.d/zz-limesurvey-production.ini
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/limesurvey-entrypoint

EXPOSE 9000

STOPSIGNAL SIGQUIT

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD kill -0 1 && php-fpm -t || exit 1

ENTRYPOINT ["limesurvey-entrypoint"]
CMD ["php-fpm"]
