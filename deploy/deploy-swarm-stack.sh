#!/bin/sh
set -eu
set +x

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STACK_FILE=${STACK_FILE:-"$SCRIPT_DIR/swarm-stack.yaml"}
ENV_FILE=${1:-"$SCRIPT_DIR/.env"}
WAIT_SECONDS=${WAIT_SECONDS:-600}

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_variable() {
  name=$1
  eval "value=\${$name-}"
  [ -n "$value" ] || fail "$name is required"
}

[ -f "$ENV_FILE" ] || fail "deployment environment file not found"
[ ! -L "$ENV_FILE" ] || fail "deployment environment file must not be a symbolic link"
permissions=$(stat -c '%a' "$ENV_FILE" 2>/dev/null || true)
owner=$(stat -c '%u' "$ENV_FILE" 2>/dev/null || true)
case "$permissions" in
  400|600) ;;
  *) fail "deployment environment file must have mode 0400 or 0600" ;;
esac
[ "$owner" = "$(id -u)" ] || fail "deployment environment file must be owned by the current user"

set -a
. "$ENV_FILE"
set +a

for name in \
  STACK_NAME APP_DOMAIN TRAEFIK_ACME_EMAIL TRAEFIK_DASHBOARD_DOMAIN \
  TRAEFIK_WHOAMI_DOMAIN TRAEFIK_DASHBOARD_USERS_FILE \
  ITDA_GLM_DASHBOARD_BASIC_AUTH_USERS BACKEND_IMAGE WEB_IMAGE \
  ITDA_POSTGRES_DB ITDA_POSTGRES_ADMIN_USER ITDA_POSTGRES_ADMIN_PASSWORD \
  ITDA_RUNTIME_ROLE ITDA_RUNTIME_PASSWORD ITDA_LABEL_BUILDER_ROLE \
  ITDA_LABEL_BUILDER_PASSWORD ITDA_LABEL_APPROVER_ROLE \
  ITDA_LABEL_APPROVER_PASSWORD ITDA_PROFILE_RELEASE_AUTHORITY_SERVICE_PASSWORD \
  ITDA_PHOTO_SERVICE_PASSWORD ITDA_PROFILE_SESSION_SERVICE_PASSWORD \
  ITDA_DAILY_GLM_REFRESH_SERVICE_PASSWORD ITDA_PROFILE_SESSION_CURRENT_KID \
  ITDA_PROFILE_SESSION_KEYRING ITDA_DAILY_GLM_REFRESH_ENABLED \
  ITDA_DAILY_GLM_REFRESH_AUTHORITY_SHA256 ITDA_TOUR_API_SERVICE_KEY_SECRET \
  ITDA_ZHIPUAI_API_KEY_SECRET ITDA_DAILY_GLM_REFRESH_SERVICE_PASSWORD_SECRET
do
  require_variable "$name"
done

[ "$APP_DOMAIN" = "it-da.app" ] || fail "APP_DOMAIN must be it-da.app"
[ "$ITDA_DAILY_GLM_REFRESH_ENABLED" = "1" ] || fail "daily GLM refresh must be enabled"
[ "$ITDA_DAILY_GLM_REFRESH_AUTHORITY_SHA256" = "060c06e8aac3f786413b6298e58b6fcf43638fa5e351d5aabab064069ec7959c" ] || fail "daily GLM refresh authority is invalid"
[ -f "$TRAEFIK_DASHBOARD_USERS_FILE" ] || fail "dashboard users file not found"
[ ! -L "$TRAEFIK_DASHBOARD_USERS_FILE" ] || fail "dashboard users file must not be a symbolic link"
dashboard_permissions=$(stat -c '%a' "$TRAEFIK_DASHBOARD_USERS_FILE" 2>/dev/null || true)
dashboard_owner=$(stat -c '%u' "$TRAEFIK_DASHBOARD_USERS_FILE" 2>/dev/null || true)
case "$dashboard_permissions" in
  400|600) ;;
  *) fail "dashboard users file must have mode 0400 or 0600" ;;
esac
[ "$dashboard_owner" = "$(id -u)" ] || fail "dashboard users file must be owned by the current user"

validate_identifier() {
  name=$1
  eval "identifier=\${$name}"
  case "$identifier" in
    ''|[!a-z_]*|*[!a-z0-9_]*) fail "$name is invalid" ;;
  esac
  [ "${#identifier}" -le 63 ] || fail "$name is invalid"
}

case "$STACK_NAME" in
  ''|[!a-z0-9]*|*[!a-z0-9_-]*) fail "STACK_NAME is invalid" ;;
esac
[ "${#STACK_NAME}" -le 63 ] || fail "STACK_NAME is invalid"

for name in ITDA_POSTGRES_DB ITDA_POSTGRES_ADMIN_USER ITDA_RUNTIME_ROLE \
  ITDA_LABEL_BUILDER_ROLE ITDA_LABEL_APPROVER_ROLE
do
  validate_identifier "$name"
done
unset identifier

case "$ITDA_PROFILE_SESSION_CURRENT_KID" in
  ''|*[!A-Za-z0-9_-]*) fail "ITDA_PROFILE_SESSION_CURRENT_KID is invalid" ;;
esac
[ "${#ITDA_PROFILE_SESSION_CURRENT_KID}" -le 24 ] || fail "ITDA_PROFILE_SESSION_CURRENT_KID is invalid"

for name in ITDA_TOUR_API_SERVICE_KEY_SECRET ITDA_ZHIPUAI_API_KEY_SECRET \
  ITDA_DAILY_GLM_REFRESH_SERVICE_PASSWORD_SECRET
do
  eval "secret_name=\${$name}"
  case "$secret_name" in
    ''|[!A-Za-z0-9_]*|*[!A-Za-z0-9_.-]*) fail "$name is invalid" ;;
  esac
done
unset secret_name

validate_url_safe_secret() {
  name=$1
  eval "value=\${$name}"
  case "$value" in
    *[!A-Za-z0-9_-]*) fail "$name must contain only URL-safe characters" ;;
  esac
  [ "${#value}" -ge 32 ] || fail "$name is invalid"
}

for name in \
  ITDA_POSTGRES_ADMIN_PASSWORD ITDA_RUNTIME_PASSWORD \
  ITDA_LABEL_BUILDER_PASSWORD ITDA_LABEL_APPROVER_PASSWORD \
  ITDA_PROFILE_RELEASE_AUTHORITY_SERVICE_PASSWORD ITDA_PHOTO_SERVICE_PASSWORD \
  ITDA_PROFILE_SESSION_SERVICE_PASSWORD ITDA_DAILY_GLM_REFRESH_SERVICE_PASSWORD
do
  validate_url_safe_secret "$name"
done

case "$ITDA_PROFILE_SESSION_KEYRING" in
  "${ITDA_PROFILE_SESSION_CURRENT_KID}."*) ;;
  *) fail "profile session keyring does not match the current key id" ;;
esac
keyring_value=${ITDA_PROFILE_SESSION_KEYRING#*.}
case "$keyring_value" in
  *[!A-Za-z0-9_-]*) fail "profile session keyring is invalid" ;;
esac
[ "${#keyring_value}" -eq 43 ] || fail "profile session keyring is invalid"
unset keyring_value value

manager=$(docker info --format '{{.Swarm.ControlAvailable}}' 2>/dev/null || true)
[ "$manager" = "true" ] || fail "run this command on a Docker Swarm manager"

docker stack services "$STACK_NAME" >/dev/null 2>&1 || fail "STACK_NAME must identify the existing Traefik stack"
traefik_service=$(docker stack services "$STACK_NAME" --filter "name=${STACK_NAME}_traefik" --format '{{.Name}}' 2>/dev/null || true)
[ "$traefik_service" = "${STACK_NAME}_traefik" ] || fail "the selected stack does not contain its Traefik service"

network=${TRAEFIK_NETWORK:-proxy}
network_state=$(docker network inspect "$network" --format '{{.Driver}}/{{.Scope}}' 2>/dev/null || true)
[ "$network_state" = "overlay/swarm" ] || fail "external Traefik network must be an overlay/swarm network"

labelled_nodes=$(docker node ls --filter node.label=itda.data=true --format '{{.ID}}' 2>/dev/null | wc -l | tr -d ' ')
[ "$labelled_nodes" -eq 1 ] || fail "exactly one Swarm node must have itda.data=true"

export TRAEFIK_NETWORK=${TRAEFIK_NETWORK:-proxy}
export TRAEFIK_CERT_RESOLVER=${TRAEFIK_CERT_RESOLVER:-le}
export TRAEFIK_IMAGE=${TRAEFIK_IMAGE:-traefik:v3.6}
export WHOAMI_IMAGE=${WHOAMI_IMAGE:-traefik/whoami}
export POSTGRES_IMAGE=${POSTGRES_IMAGE:-docker.io/library/postgres:17.10-bookworm@sha256:4f736ae292687621d4dbe0d499ffd024a36bd2ee7d8ca6f2ccd4c800f047b394}

docker stack config --compose-file "$STACK_FILE" >/dev/null

create_secret_from_variable() {
  secret_name=$1
  variable_name=$2
  if docker secret inspect "$secret_name" >/dev/null 2>&1; then
    printf 'Using existing Docker secret: %s\n' "$secret_name"
    return
  fi
  eval "secret_value=\${$variable_name}"
  printf %s "$secret_value" | docker secret create "$secret_name" - >/dev/null
  printf 'Created Docker secret: %s\n' "$secret_name"
}

create_secret_from_file() {
  secret_name=$1
  source_file=$2
  if docker secret inspect "$secret_name" >/dev/null 2>&1; then
    printf 'Using existing Docker secret: %s\n' "$secret_name"
    return
  fi
  docker secret create "$secret_name" "$source_file" >/dev/null
  printf 'Created Docker secret: %s\n' "$secret_name"
}

create_secret_from_file traefik_dashboard_users "$TRAEFIK_DASHBOARD_USERS_FILE"
create_secret_from_variable itda_admin_password ITDA_POSTGRES_ADMIN_PASSWORD
create_secret_from_variable itda_runtime_password ITDA_RUNTIME_PASSWORD
create_secret_from_variable itda_label_builder_password ITDA_LABEL_BUILDER_PASSWORD
create_secret_from_variable itda_label_approver_password ITDA_LABEL_APPROVER_PASSWORD
create_secret_from_variable itda_profile_release_authority_service_password ITDA_PROFILE_RELEASE_AUTHORITY_SERVICE_PASSWORD
create_secret_from_variable itda_photo_service_password ITDA_PHOTO_SERVICE_PASSWORD
create_secret_from_variable itda_profile_session_service_password ITDA_PROFILE_SESSION_SERVICE_PASSWORD
create_secret_from_variable "$ITDA_DAILY_GLM_REFRESH_SERVICE_PASSWORD_SECRET" ITDA_DAILY_GLM_REFRESH_SERVICE_PASSWORD
keyring_secret="itda_profile_session_keyring_${ITDA_PROFILE_SESSION_CURRENT_KID}"
create_secret_from_variable "$keyring_secret" ITDA_PROFILE_SESSION_KEYRING
for secret_name in "$ITDA_TOUR_API_SERVICE_KEY_SECRET" "$ITDA_ZHIPUAI_API_KEY_SECRET"
do
  docker secret inspect "$secret_name" >/dev/null 2>&1 || fail "required provider Docker secret is missing"
done

unset ITDA_POSTGRES_ADMIN_PASSWORD ITDA_RUNTIME_PASSWORD
unset ITDA_LABEL_BUILDER_PASSWORD ITDA_LABEL_APPROVER_PASSWORD
unset ITDA_PROFILE_RELEASE_AUTHORITY_SERVICE_PASSWORD ITDA_PHOTO_SERVICE_PASSWORD
unset ITDA_PROFILE_SESSION_SERVICE_PASSWORD ITDA_DAILY_GLM_REFRESH_SERVICE_PASSWORD
unset ITDA_PROFILE_SESSION_KEYRING
unset keyring_secret secret_name secret_value

docker stack deploy --with-registry-auth --compose-file "$STACK_FILE" "$STACK_NAME"

wait_for_completed() {
  service=$1
  deadline=$(( $(date +%s) + WAIT_SECONDS ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    state=$(docker service ps "$service" --no-trunc --format '{{.CurrentState}}' 2>/dev/null | sed -n '1p')
    case "$state" in
      Complete*) return 0 ;;
    esac
    sleep 3
  done
  docker service ps "$service" --no-trunc >&2 || true
  docker service logs --tail 50 "$service" >&2 || true
  fail "$service did not complete within the deployment timeout"
}

wait_for_replica() {
  service=$1
  deadline=$(( $(date +%s) + WAIT_SECONDS ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    replicas=$(docker service ls --filter "name=$service" --format '{{.Replicas}}' 2>/dev/null | sed -n '1p')
    [ "$replicas" = "1/1" ] && return 0
    sleep 3
  done
  docker service ps "$service" --no-trunc >&2 || true
  fail "$service did not converge within the deployment timeout"
}

wait_for_completed "${STACK_NAME}_migrate"
wait_for_completed "${STACK_NAME}_quarantine-init"
for service in traefik whoami postgres backend daily-glm-refresh web
do
  wait_for_replica "${STACK_NAME}_${service}"
done

wait_for_status() {
  url=$1
  expected=$2
  deadline=$(( $(date +%s) + WAIT_SECONDS ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    status=$(curl --silent --output /dev/null --write-out '%{http_code}' "$url" || true)
    [ "$status" = "$expected" ] && return 0
    sleep 5
  done
  fail "external deployment verification failed for $url"
}

wait_for_status "https://${APP_DOMAIN}/" 200
wait_for_status "https://${APP_DOMAIN}/v1/questionnaires/current" 200
wait_for_status "https://${APP_DOMAIN}/internal" 404
wait_for_status "https://${APP_DOMAIN}/internal/evaluation/profile-releases/probe" 404

printf 'Swarm stack deployed and verified: %s\n' "$STACK_NAME"
