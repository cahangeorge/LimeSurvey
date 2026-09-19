#!/bin/sh
set -eu

project_name=${COMPOSE_PROJECT_NAME:-limesurvey-smoke}
env_file=${ENV_FILE:-.env.example}
keep_stack=${KEEP_SMOKE_STACK:-0}
runtime_fixture_dir=/var/www/html/tmp/runtime/limesurvey-nginx-protection-smoke-2fb6bdb
runtime_fixture=$runtime_fixture_dir/limesurvey-nginx-protection-smoke-2fb6bdb.txt
upload_survey_dir=/var/www/html/upload/surveys/987654321
upload_files_dir=$upload_survey_dir/files
upload_fixture=$upload_files_dir/fu_limesurvey-nginx-protection-smoke-2fb6bdb.txt

compose() {
    docker compose --project-name "$project_name" --env-file "$env_file" "$@"
}

cleanup() {
    compose exec -T app sh -c '
        rm -f -- "$1" "$2"
        rmdir -- "$3" 2>/dev/null || true
        rmdir -- "$4" 2>/dev/null || true
        rmdir -- "$5" 2>/dev/null || true
    ' sh "$runtime_fixture" "$upload_fixture" "$runtime_fixture_dir" \
        "$upload_files_dir" "$upload_survey_dir" >/dev/null 2>&1 || true

    if [ "$keep_stack" != 1 ]; then
        compose down --remove-orphans >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT INT TERM

container_for_service() {
    expected_service=$1

    for candidate_id in $(compose ps -q); do
        candidate_service=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "$candidate_id" 2>/dev/null || true)
        if [ -z "$candidate_service" ]; then
            candidate_service=$(docker inspect --format '{{index .Config.Labels "io.podman.compose.service"}}' "$candidate_id" 2>/dev/null || true)
        fi
        if [ "$candidate_service" = "$expected_service" ]; then
            printf '%s\n' "$candidate_id"
            return 0
        fi
    done

    return 1
}

wait_for_health() {
    service=$1
    attempts=${2:-30}

    while [ "$attempts" -gt 0 ]; do
        container_id=$(container_for_service "$service" || true)
        if [ -n "$container_id" ]; then
            health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id")
            case "$health" in
                healthy|running)
                    return 0
                    ;;
                unhealthy|exited|dead)
                    compose logs --no-color "$service" >&2 || true
                    return 1
                    ;;
            esac
        fi
        attempts=$((attempts - 1))
        sleep 2
    done

    compose logs --no-color "$service" >&2 || true
    echo "Timed out waiting for $service to become healthy" >&2
    return 1
}

compose config --quiet
compose up -d --build

wait_for_health db 45
wait_for_health app 45
wait_for_health nginx 45

db_container=$(container_for_service db)
if docker port "$db_container" 3306/tcp 2>/dev/null | grep -q .; then
    echo 'Database port must not be published on the host' >&2
    exit 1
fi

compose exec -T nginx wget -qO- http://127.0.0.1/healthz \
    | grep -qx 'ok'

compose exec -T nginx wget -qO /dev/null http://127.0.0.1/

compose exec -T nginx wget -qO- http://127.0.0.1/editor/ \
    | grep -Fq '<title>LimeSurvey - Editor</title>'

compose exec -T app sh -eu -c '
    mkdir -p "$1" "$2"
    printf "%s\n" nginx-protection-smoke > "$3"
    printf "%s\n" nginx-protection-smoke > "$4"
' sh "$runtime_fixture_dir" "$upload_files_dir" "$runtime_fixture" "$upload_fixture"

compose exec -T app sh -eu -c '
    test -f /var/www/html/plugins/ResendEmail/ResendEmail.php
    test -f /var/www/html/plugins/ResendEmail/ResendClient.php
    test -f /var/www/html/plugins/ResendEmail/config.xml
    php -r '\''
        $config = simplexml_load_file("/var/www/html/plugins/ResendEmail/config.xml");
        if ($config === false || (string) $config->metadata->name !== "ResendEmail") {
            fwrite(STDERR, "ResendEmail metadata is unavailable.\n");
            exit(1);
        }
    '\''
'

if compose exec -T nginx wget -qO /dev/null \
    http://127.0.0.1/application/config/config.php; then
    echo 'Nginx exposed an internal configuration file' >&2
    exit 1
fi

if compose exec -T nginx wget -qO /dev/null \
    http://127.0.0.1/open-api-gen.php; then
    echo 'Nginx executed a non-front-controller PHP script' >&2
    exit 1
fi

if compose exec -T nginx wget -qO /dev/null \
    http://127.0.0.1/tmp/runtime/limesurvey-nginx-protection-smoke-2fb6bdb/limesurvey-nginx-protection-smoke-2fb6bdb.txt; then
    echo 'Nginx exposed a LimeSurvey runtime fixture' >&2
    exit 1
fi

if compose exec -T nginx wget -qO /dev/null \
    http://127.0.0.1/upload/surveys/987654321/files/fu_limesurvey-nginx-protection-smoke-2fb6bdb.txt; then
    echo 'Nginx exposed a LimeSurvey response-upload fixture' >&2
    exit 1
fi

compose exec -T db sh -eu -c '
    export MYSQL_PWD=$MARIADB_PASSWORD
    mariadb --user="$MARIADB_USER" "$MARIADB_DATABASE" <<SQL
CREATE TABLE IF NOT EXISTS deployment_smoke_marker (
    id INT PRIMARY KEY,
    marker VARCHAR(32) NOT NULL
);
INSERT INTO deployment_smoke_marker (id, marker)
VALUES (1, "persistent")
ON DUPLICATE KEY UPDATE marker = VALUES(marker);
SQL
'

compose up -d --force-recreate db
wait_for_health db 45

marker=$(compose exec -T db sh -eu -c '
    export MYSQL_PWD=$MARIADB_PASSWORD
    mariadb --batch --skip-column-names --user="$MARIADB_USER" \
        "$MARIADB_DATABASE" \
        --execute="SELECT marker FROM deployment_smoke_marker WHERE id = 1"
')
test "$marker" = persistent

compose ps
echo 'compose_smoke=ok'
