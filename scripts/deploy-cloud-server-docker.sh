#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] || die "$2 must be an integer"
    (( 1 <= 10#$1 && 10#$1 <= 65535 )) || die "$2 must be between 1 and 65535"
}

validate_safe_value() {
    [[ "$2" =~ ^[A-Za-z0-9_./:@+,-]+$ ]] || die "$1 contains unsupported characters"
}

validate_name() {
    [[ "$2" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "$1 contains unsupported characters"
}

wait_for_remote_health() {
    local container_name="$1"
    local status="" attempt
    for attempt in $(seq 1 60); do
        status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' \
            "$container_name" 2>/dev/null || true)"
        if [[ "$status" == "healthy" ]]; then
            return 0
        fi
        if [[ "$status" == "unhealthy" ]]; then
            break
        fi
        sleep 1
    done
    docker logs --tail 100 "$container_name" >&2 || true
    die "container did not become healthy (status: ${status:-unknown})"
}

install_on_server() {
    local remote_root="$2"
    local revision="$3"
    local host_port="$4"
    local container_name="$5"
    local volume_name="$6"
    local update_superadmins="$7"
    local requested_superadmins="$8"
    local log_level="${9}"
    local release_dir="$remote_root/releases/$revision"
    local secret_env="$remote_root/secrets.env"
    local runtime_env="$remote_root/runtime.env"
    local image="cloakbrowser-cloud:$revision"
    local superadmins=""

    if [[ "$requested_superadmins" == "__CLOAK_EMPTY__" ]]; then
        requested_superadmins=""
    fi

    [[ "$(id -u)" == "0" ]] || die "remote installation must run as root"
    require_command docker
    require_command openssl
    validate_port "$host_port" CLOUD_PORT
    validate_name CLOUD_CONTAINER_NAME "$container_name"
    validate_name CLOUD_VOLUME_NAME "$volume_name"
    [[ -f "$release_dir/Dockerfile.cloud" ]] || die "uploaded release is incomplete"
    docker info >/dev/null 2>&1 || die "remote Docker daemon is not running"

    install -d -m 0700 "$remote_root"
    if [[ ! -f "$secret_env" ]]; then
        local app_secret snapshot_key
        app_secret="$(openssl rand -hex 48)"
        snapshot_key="$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '\n')"
        umask 077
        {
            printf 'CLOAKBROWSER_CLOUD_DATABASE_URL=sqlite:////data/cloud.db\n'
            printf 'CLOAKBROWSER_CLOUD_SECRET=%s\n' "$app_secret"
            printf 'CLOAKBROWSER_CLOUD_SNAPSHOT_KEY=%s\n' "$snapshot_key"
        } >"$secret_env"
    fi

    if [[ -f "$runtime_env" ]]; then
        superadmins="$(sed -n 's/^CLOAKBROWSER_CLOUD_SUPERADMIN_EMAILS=//p' "$runtime_env" | tail -n 1)"
    fi
    if [[ "$update_superadmins" == "1" ]]; then
        superadmins="$requested_superadmins"
    fi
    [[ "$superadmins" =~ ^[A-Za-z0-9@+._,-]*$ ]] \
        || die "CLOUD_SUPERADMIN_EMAILS must be comma-separated email addresses without spaces"
    [[ "$log_level" =~ ^(critical|error|warning|info|debug|trace)$ ]] \
        || die "CLOUD_LOG_LEVEL must be critical, error, warning, info, debug, or trace"
    umask 077
    {
        printf 'CLOAKBROWSER_CLOUD_COOKIE_SECURE=true\n'
        printf 'CLOAKBROWSER_CLOUD_LOG_LEVEL=%s\n' "$log_level"
        printf 'CLOAKBROWSER_CLOUD_SUPERADMIN_EMAILS=%s\n' "$superadmins"
    } >"$runtime_env"
    chmod 0600 "$secret_env" "$runtime_env"

    printf 'Building %s on the server...\n' "$image"
    docker build \
        --file "$release_dir/Dockerfile.cloud" \
        --build-arg "SOURCE_REVISION=$revision" \
        --tag "$image" \
        "$release_dir"

    if docker container inspect "$container_name" >/dev/null 2>&1; then
        docker rm --force "$container_name" >/dev/null
    fi

    docker run --detach \
        --name "$container_name" \
        --restart unless-stopped \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,size=64m \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --pids-limit 256 \
        --env-file "$secret_env" \
        --env-file "$runtime_env" \
        --publish "127.0.0.1:${host_port}:8777" \
        --mount "type=volume,source=${volume_name},target=/data" \
        --label com.cloakbrowser.component=cloud \
        --label "com.cloakbrowser.revision=$revision" \
        "$image" >/dev/null

    wait_for_remote_health "$container_name"
    printf 'CloakBrowser Cloud container is healthy on 127.0.0.1:%s\n' "$host_port"
    printf 'Persistent data volume: %s\n' "$volume_name"
    printf 'Protected configuration: %s\n' "$remote_root"
}

if [[ "${1:-}" == "--install-on-server" ]]; then
    [[ "$#" == "9" ]] || die "invalid internal server invocation"
    install_on_server "$@"
    exit 0
fi

TARGET="${1:-${CLOUD_SSH_TARGET:-}}"
SSH_PORT="${2:-${CLOUD_SSH_PORT:-22}}"
[[ -n "$TARGET" ]] || die "usage: $0 user@server [ssh-port]"

CLOUD_REMOTE_ROOT="${CLOUD_REMOTE_ROOT:-/opt/cloakbrowser-cloud-docker}"
CLOUD_PORT="${CLOUD_PORT:-18777}"
CLOUD_CONTAINER_NAME="${CLOUD_CONTAINER_NAME:-cloakbrowser-cloud}"
CLOUD_VOLUME_NAME="${CLOUD_VOLUME_NAME:-cloakbrowser-cloud-data}"
CLOUD_PUBLIC_URL="${CLOUD_PUBLIC_URL:-}"
SUPERADMIN_UPDATE=0
SUPERADMIN_VALUE=""
if [[ "${CLOUD_SUPERADMIN_EMAILS+x}" == "x" ]]; then
    SUPERADMIN_UPDATE=1
    SUPERADMIN_VALUE="$CLOUD_SUPERADMIN_EMAILS"
fi
SUPERADMIN_ARG="${SUPERADMIN_VALUE:-__CLOAK_EMPTY__}"
LOG_LEVEL="${CLOUD_LOG_LEVEL:-info}"

require_command git
require_command ssh
require_command scp
require_command mktemp
validate_port "$SSH_PORT" CLOUD_SSH_PORT
validate_port "$CLOUD_PORT" CLOUD_PORT
validate_safe_value CLOUD_SSH_TARGET "$TARGET"
validate_safe_value CLOUD_REMOTE_ROOT "$CLOUD_REMOTE_ROOT"
validate_name CLOUD_CONTAINER_NAME "$CLOUD_CONTAINER_NAME"
validate_name CLOUD_VOLUME_NAME "$CLOUD_VOLUME_NAME"
[[ "$SUPERADMIN_VALUE" =~ ^[A-Za-z0-9@+._,-]*$ ]] \
    || die "CLOUD_SUPERADMIN_EMAILS must be comma-separated email addresses without spaces"
[[ "$LOG_LEVEL" =~ ^(critical|error|warning|info|debug|trace)$ ]] \
    || die "CLOUD_LOG_LEVEL must be critical, error, warning, info, debug, or trace"
if [[ -n "$CLOUD_PUBLIC_URL" && ! "$CLOUD_PUBLIC_URL" =~ ^https://[^[:space:]]+$ ]]; then
    die "CLOUD_PUBLIC_URL must be an HTTPS URL"
fi

[[ -z "$(git -C "$REPO_ROOT" status --porcelain)" ]] \
    || die "working tree is not clean; commit changes before deploying"

revision="$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD)"
archive="$(mktemp "${TMPDIR:-/tmp}/cloakbrowser-cloud.XXXXXX.tar.gz")"
trap 'rm -f "$archive"' EXIT
git -C "$REPO_ROOT" archive --format=tar.gz --output="$archive" HEAD

SSH=(ssh -p "$SSH_PORT" -o BatchMode=yes "$TARGET")
SCP=(scp -P "$SSH_PORT" -o BatchMode=yes)
remote_archive="$CLOUD_REMOTE_ROOT/releases/$revision.tar.gz"
remote_release="$CLOUD_REMOTE_ROOT/releases/$revision"

"${SSH[@]}" "install -d -m 0700 $CLOUD_REMOTE_ROOT/releases"
"${SCP[@]}" "$archive" "$TARGET:$remote_archive"
"${SSH[@]}" "set -e; install -d -m 0755 $remote_release; tar -xzf $remote_archive -C $remote_release; rm -f $remote_archive"
"${SSH[@]}" \
    "bash $remote_release/scripts/deploy-cloud-server-docker.sh --install-on-server $CLOUD_REMOTE_ROOT $revision $CLOUD_PORT $CLOUD_CONTAINER_NAME $CLOUD_VOLUME_NAME $SUPERADMIN_UPDATE $SUPERADMIN_ARG $LOG_LEVEL"

printf '\nServer deployment completed:\n'
printf '  Upstream:   http://127.0.0.1:%s (on %s)\n' "$CLOUD_PORT" "$TARGET"
printf '  Container:  %s\n' "$CLOUD_CONTAINER_NAME"
if [[ -n "$CLOUD_PUBLIC_URL" ]]; then
    printf '  Public URL: %s\n' "$CLOUD_PUBLIC_URL"
else
    printf '  Next: point an HTTPS reverse proxy at 127.0.0.1:%s\n' "$CLOUD_PORT"
fi
