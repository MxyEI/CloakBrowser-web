#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CLOUD_PORT="${CLOUD_PORT:-8777}"
CLOUD_CONTAINER_NAME="${CLOUD_CONTAINER_NAME:-cloakbrowser-cloud-local}"
CLOUD_VOLUME_NAME="${CLOUD_VOLUME_NAME:-cloakbrowser-cloud-local-data}"
CLOUD_IMAGE="${CLOUD_IMAGE:-cloakbrowser-cloud:local}"
CLOUD_STATE_DIR="${CLOUD_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/cloakbrowser-cloud-local}"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] || die "CLOUD_PORT must be an integer"
    (( 1 <= 10#$1 && 10#$1 <= 65535 )) || die "CLOUD_PORT must be between 1 and 65535"
}

validate_name() {
    [[ "$2" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "$1 contains unsupported characters"
}

validate_superadmins() {
    [[ "$1" =~ ^[A-Za-z0-9@+._,-]*$ ]] \
        || die "CLOUD_SUPERADMIN_EMAILS must be comma-separated email addresses without spaces"
}

validate_log_level() {
    [[ "$1" =~ ^(critical|error|warning|info|debug|trace)$ ]] \
        || die "CLOUD_LOG_LEVEL must be critical, error, warning, info, debug, or trace"
}

write_secret_env() {
    local target="$1"
    local app_secret snapshot_key
    app_secret="$(openssl rand -hex 48)"
    snapshot_key="$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '\n')"
    umask 077
    {
        printf 'CLOAKBROWSER_CLOUD_DATABASE_URL=sqlite:////data/cloud.db\n'
        printf 'CLOAKBROWSER_CLOUD_SECRET=%s\n' "$app_secret"
        printf 'CLOAKBROWSER_CLOUD_SNAPSHOT_KEY=%s\n' "$snapshot_key"
    } >"$target"
}

write_runtime_env() {
    local target="$1"
    local superadmins=""
    local log_level="${CLOUD_LOG_LEVEL:-info}"
    if [[ -f "$target" ]]; then
        superadmins="$(sed -n 's/^CLOAKBROWSER_CLOUD_SUPERADMIN_EMAILS=//p' "$target" | tail -n 1)"
    fi
    if [[ "${CLOUD_SUPERADMIN_EMAILS+x}" == "x" ]]; then
        superadmins="$CLOUD_SUPERADMIN_EMAILS"
    fi
    validate_superadmins "$superadmins"
    validate_log_level "$log_level"
    umask 077
    {
        printf 'CLOAKBROWSER_CLOUD_COOKIE_SECURE=false\n'
        printf 'CLOAKBROWSER_CLOUD_LOG_LEVEL=%s\n' "$log_level"
        printf 'CLOAKBROWSER_CLOUD_SUPERADMIN_EMAILS=%s\n' "$superadmins"
    } >"$target"
}

wait_for_health() {
    local status=""
    local attempt
    for attempt in $(seq 1 60); do
        status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' \
            "$CLOUD_CONTAINER_NAME" 2>/dev/null || true)"
        if [[ "$status" == "healthy" ]]; then
            return 0
        fi
        if [[ "$status" == "unhealthy" ]]; then
            break
        fi
        sleep 1
    done
    docker logs --tail 100 "$CLOUD_CONTAINER_NAME" >&2 || true
    die "container did not become healthy (status: ${status:-unknown})"
}

require_command docker
require_command openssl
validate_port "$CLOUD_PORT"
validate_name CLOUD_CONTAINER_NAME "$CLOUD_CONTAINER_NAME"
validate_name CLOUD_VOLUME_NAME "$CLOUD_VOLUME_NAME"

docker info >/dev/null 2>&1 || die "Docker daemon is not running"

install -d -m 0700 "$CLOUD_STATE_DIR"
SECRET_ENV="$CLOUD_STATE_DIR/secrets.env"
RUNTIME_ENV="$CLOUD_STATE_DIR/runtime.env"
[[ -f "$SECRET_ENV" ]] || write_secret_env "$SECRET_ENV"
write_runtime_env "$RUNTIME_ENV"
chmod 0600 "$SECRET_ENV" "$RUNTIME_ENV"

revision="$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD 2>/dev/null || printf 'working-tree')"
printf 'Building %s from %s...\n' "$CLOUD_IMAGE" "$revision"
docker build \
    --file "$REPO_ROOT/Dockerfile.cloud" \
    --build-arg "SOURCE_REVISION=$revision" \
    --tag "$CLOUD_IMAGE" \
    "$REPO_ROOT"

if docker container inspect "$CLOUD_CONTAINER_NAME" >/dev/null 2>&1; then
    docker rm --force "$CLOUD_CONTAINER_NAME" >/dev/null
fi

docker run --detach \
    --name "$CLOUD_CONTAINER_NAME" \
    --restart unless-stopped \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 256 \
    --env-file "$SECRET_ENV" \
    --env-file "$RUNTIME_ENV" \
    --publish "127.0.0.1:${CLOUD_PORT}:8777" \
    --mount "type=volume,source=${CLOUD_VOLUME_NAME},target=/data" \
    --label com.cloakbrowser.component=cloud \
    "$CLOUD_IMAGE" \
    --container-loopback >/dev/null

wait_for_health

printf '\nCloakBrowser Cloud is ready:\n'
printf '  URL:        http://127.0.0.1:%s\n' "$CLOUD_PORT"
printf '  Container:  %s\n' "$CLOUD_CONTAINER_NAME"
printf '  Data:       Docker volume %s\n' "$CLOUD_VOLUME_NAME"
printf '  Config:     %s\n' "$CLOUD_STATE_DIR"
