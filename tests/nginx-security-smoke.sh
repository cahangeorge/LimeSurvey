#!/bin/sh
set -eu

# Disposable proxy test, using synthetic files and a previously built FPM image.
# This proves local Nginx behavior, not LimeSurvey or native ARM64 acceptance.
engine=${CONTAINER_ENGINE:-docker}
: "${NGINX_IMAGE:?Set an immutable local NGINX_IMAGE ID}"
: "${FPM_IMAGE:?Set an immutable local FPM_IMAGE ID}"
for image in "$NGINX_IMAGE" "$FPM_IMAGE"; do
    image_id=${image#sha256:}
    [ "${#image_id}" -eq 64 ] || { echo 'FAIL: use full local image IDs' >&2; exit 1; }
    case "$image_id" in
        *[!0-9a-f]*) echo 'FAIL: invalid image ID' >&2; exit 1 ;;
    esac
done
command -v "$engine" >/dev/null
printf 'NGINX_IMAGE=%s\nFPM_IMAGE=%s\n' "$NGINX_IMAGE" "$FPM_IMAGE"
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
scratch=$(mktemp -d)
network=
remove_resources() {
    failed=0
    for cid_file in "$scratch/nginx.cid" "$scratch/fpm.cid"; do
        if [ -s "$cid_file" ]; then
            if "$engine" rm --force "$(cat "$cid_file")" >/dev/null; then
                rm -f "$cid_file"
            else
                failed=1
            fi
        fi
    done
    if [ -n "$network" ]; then
        if "$engine" network rm "$network" >/dev/null; then
            network=
        else
            failed=1
        fi
    fi
    return "$failed"
}
cleanup() {
    status=$?
    trap - EXIT
    if ! remove_resources; then
        echo 'FAIL: owned test resources remain; cleanup required' >&2
        [ "$status" -ne 0 ] || status=1
    fi
    rm -rf "$scratch"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

chmod 755 "$scratch"
mkdir -p "$scratch/html/application/config" "$scratch/html/vendor" \
    "$scratch/html/docs" "$scratch/html/tests" "$scratch/html/tmp/runtime" \
    "$scratch/html/upload/surveys/1/files"
printf '%s' 'static-ok' > "$scratch/html/probe.txt"
printf '%s' '<?php echo "fpm-ok|".($_SERVER["PATH_INFO"]??"")."|".($_SERVER["HTTPS"]??"")."|".($_SERVER["HTTP_PROXY"]??"");' > "$scratch/html/index.php"
for file in .hidden application/config/probe.txt vendor/probe.txt docs/probe.txt \
    tests/probe.txt tmp/runtime/probe.txt upload/surveys/1/files/fu_private unexpected.php; do
    printf '%s' 'must-not-be-served' > "$scratch/html/$file"
done

network=$("$engine" network create --internal "limesurvey-nginx-smoke-$$")
"$engine" create --pull=never --cidfile "$scratch/fpm.cid" --network "$network" \
    --network-alias app --read-only --tmpfs /tmp \
    --volume "$scratch/html:/var/www/html:ro" --entrypoint php-fpm \
    "$FPM_IMAGE" >/dev/null
"$engine" start "$(cat "$scratch/fpm.cid")" >/dev/null
"$engine" create --pull=never --cidfile "$scratch/nginx.cid" --network "$network" \
    --read-only --tmpfs /var/cache/nginx --tmpfs /var/run --tmpfs /tmp \
    --volume "$scratch/html:/var/www/html:ro" \
    --volume "$root/docker/nginx/default.conf:/etc/nginx/conf.d/default.conf:ro" \
    "$NGINX_IMAGE" >/dev/null
nginx=$(cat "$scratch/nginx.cid")
"$engine" start "$nginx" >/dev/null

attempt=0
until "$engine" exec "$nginx" curl --fail --silent --max-time 2 \
    http://127.0.0.1/healthz >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 20 ] || { echo 'FAIL: Nginx readiness timeout' >&2; exit 1; }
    sleep 1
done
"$engine" exec "$nginx" nginx -t
body=$("$engine" exec "$nginx" curl --fail --silent --max-time 5 http://127.0.0.1/probe.txt)
[ "$body" = static-ok ] || { echo 'FAIL: static content' >&2; exit 1; }
body=$("$engine" exec "$nginx" curl --fail --silent --max-time 5 \
    --header 'X-Forwarded-Proto: https' --header 'Proxy: hostile.invalid' \
    http://127.0.0.1/index.php/probe)
[ "$body" = 'fpm-ok|/probe|on|' ] || { echo 'FAIL: FastCGI parameters' >&2; exit 1; }
for path in /.hidden /application/config/probe.txt /vendor/probe.txt /docs/probe.txt \
    /tests/probe.txt /tmp/runtime/probe.txt /upload/surveys/1/files/fu_private; do
    status=$("$engine" exec "$nginx" curl --silent --max-time 5 \
        --output /dev/null --write-out '%{http_code}' "http://127.0.0.1$path")
    [ "$status" = 403 ] || { echo 'FAIL: protected file response' >&2; exit 1; }
done
status=$("$engine" exec "$nginx" curl --silent --max-time 5 \
    --output /dev/null --write-out '%{http_code}' http://127.0.0.1/unexpected.php)
[ "$status" = 404 ] || { echo 'FAIL: unexpected PHP response' >&2; exit 1; }
remove_resources || { echo 'FAIL: owned test cleanup' >&2; exit 1; }
echo 'PASS: health, config, static, FastCGI HTTPS/path/proxy, 7 protected paths, PHP deny'
