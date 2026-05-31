#!/usr/bin/env bash
#
# lldapctl.sh - small CRUD helper for the local dev LLDAP (clients/dev).
#
# It drives user/group changes via the GraphQL API so you can watch a consumer
# (the SDK example, or files) reconcile. After each mutation it also publishes
# an os.users / os.groups NATS message, simulating app-service so the SDK's
# event path works without a real cluster (best-effort: a publish failure only
# warns and never fails the mutation).
#
# The NATS publish runs `nats pub` inside a throwaway nats-box container that
# joins the dev compose network, so this script stays self-contained: it needs
# only docker + curl + jq and no LLDAP source to build.
#
# Config via env: LLDAP_URL (default http://localhost:17170),
#                 ADMIN_USER (default alice), ADMIN_PASS (default password),
#                 NATS_NETWORK (docker network to publish on, default lldap-dev),
#                 NATS_SERVER (NATS address within that network, default nats://nats:4222),
#                 NATS_USERNAME (default lldap), NATS_PASSWORD (default secret),
#                 NATS_BOX_IMAGE (default natsio/nats-box:latest).
#
# Focus: managing who exists and who is an admin (membership in the built-in
# lldap_admin group), not editing profile fields.
#
# Examples:
#   ./lldapctl.sh create-user carol
#   ./lldapctl.sh make-admin carol
#   ./lldapctl.sh remove-admin carol
#   ./lldapctl.sh list-users

set -euo pipefail

LLDAP_URL="${LLDAP_URL:-http://localhost:17170}"
ADMIN_USER="${ADMIN_USER:-alice}"
ADMIN_PASS="${ADMIN_PASS:-password}"
NATS_NETWORK="${NATS_NETWORK:-lldap-dev}"
NATS_SERVER="${NATS_SERVER:-nats://nats:4222}"
NATS_USERNAME="${NATS_USERNAME:-lldap}"
NATS_PASSWORD="${NATS_PASSWORD:-secret}"
NATS_BOX_IMAGE="${NATS_BOX_IMAGE:-natsio/nats-box:latest}"

token=""

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }

# publish SUBJECT TOPIC [NAME] - emits an os.* trigger, mimicking app-service,
# via `nats pub` in a one-shot nats-box container on the dev compose network.
# Best-effort: a failure (docker missing, NATS/network down) only warns so the
# mutation still succeeds. The SDK treats events as triggers, so the payload is
# nominal (it mirrors app-service's {topic, payload:{...}} shape).
publish() {
  local subject="$1" topic="$2" name="${3:-}" payload
  command -v docker >/dev/null 2>&1 || { echo "warn: docker not found, skipping NATS publish" >&2; return 0; }
  payload=$(printf '{"topic":"%s","payload":{"user":"%s","operator":"lldapctl","timestamp":"%s"}}' \
    "$topic" "$name" "$(date -u +%Y-%m-%dT%H:%M:%SZ)")
  docker run --rm --network "$NATS_NETWORK" "$NATS_BOX_IMAGE" \
    nats pub --server "$NATS_SERVER" --user "$NATS_USERNAME" --password "$NATS_PASSWORD" \
    "$subject" "$payload" >/dev/null 2>&1 \
    || echo "warn: failed to publish $topic to $subject (NATS up? docker network '$NATS_NETWORK' present?)" >&2
}

login() {
  need curl
  need jq
  token=$(curl -fsS -X POST "$LLDAP_URL/auth/simple/login" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg u "$ADMIN_USER" --arg p "$ADMIN_PASS" '{username:$u,password:$p}')" \
    | jq -r '.token')
  [[ -n "$token" && "$token" != "null" ]] || { echo "login failed (check ADMIN_USER/ADMIN_PASS and that lldap is up)" >&2; exit 1; }
}

ensure_login() { [[ -n "$token" ]] || login; }

# gql QUERY [VARIABLES_JSON] -> prints the raw response JSON, exits on errors.
gql() {
  local query="$1" vars="${2:-}"
  [[ -n "$vars" ]] || vars='{}'
  local body resp
  body=$(jq -n --arg q "$query" --argjson v "$vars" '{query:$q, variables:$v}')
  resp=$(curl -fsS -X POST "$LLDAP_URL/api/graphql" \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    -d "$body")
  if echo "$resp" | jq -e '(.errors // []) | length > 0' >/dev/null 2>&1; then
    echo "graphql error: $(echo "$resp" | jq -c '.errors')" >&2
    exit 1
  fi
  echo "$resp"
}

cmd_list_users() {
  ensure_login
  gql 'query { users { id email displayName groups { displayName } } }' | jq '.data.users'
}

cmd_get_user() {
  [[ $# -eq 1 ]] || { echo "usage: get-user <id>" >&2; exit 1; }
  ensure_login
  gql 'query($id:String!){ user(userId:$id){ id email displayName firstName lastName groups{displayName} attributes{name value} } }' \
    "$(jq -n --arg id "$1" '{id:$id}')" | jq '.data.user'
}

cmd_create_user() {
  [[ $# -ge 1 ]] || { echo "usage: create-user <id> [email] [displayName]" >&2; exit 1; }
  ensure_login
  local id="$1"
  # Optional fields default off the id: <id>@$EMAIL_DOMAIN and the id capitalized.
  local email="${2:-${id}@${EMAIL_DOMAIN:-example.com}}"
  local dn="${3:-$(printf '%s' "$id" | cut -c1 | tr '[:lower:]' '[:upper:]')$(printf '%s' "$id" | cut -c2-)}"
  local vars
  vars=$(jq -n --arg id "$id" --arg email "$email" --arg dn "$dn" \
    '{u: {id:$id, email:$email, displayName:$dn}}')
  gql 'mutation($u:CreateUserInput!){ createUser(user:$u){ id email displayName } }' "$vars" | jq '.data.createUser'
  publish os.users Create "$id"
}

cmd_delete_user() {
  [[ $# -eq 1 ]] || { echo "usage: delete-user <id>" >&2; exit 1; }
  ensure_login
  gql 'mutation($id:String!){ deleteUser(userId:$id){ ok } }' "$(jq -n --arg id "$1" '{id:$id}')" | jq '.data.deleteUser'
  publish os.users Delete "$1"
}

cmd_list_groups() {
  ensure_login
  gql 'query { groups { id displayName users { id } } }' | jq '.data.groups'
}

cmd_create_group() {
  [[ $# -eq 1 ]] || { echo "usage: create-group <name>" >&2; exit 1; }
  ensure_login
  gql 'mutation($n:String!){ createGroup(name:$n){ id displayName } }' "$(jq -n --arg n "$1" '{n:$n}')" | jq '.data.createGroup'
  publish os.groups Create "$1"
}

cmd_delete_group() {
  [[ $# -eq 1 ]] || { echo "usage: delete-group <groupId>" >&2; exit 1; }
  require_int "$1"
  ensure_login
  gql 'mutation($g:Int!){ deleteGroup(groupId:$g){ ok } }' "$(jq -n --argjson g "$1" '{g:$g}')" | jq '.data.deleteGroup'
  publish os.groups Delete "$1"
}

require_int() {
  [[ "$1" =~ ^[0-9]+$ ]] || { echo "groupId must be an integer, got: $1" >&2; exit 1; }
}

cmd_add_to_group() {
  [[ $# -eq 2 ]] || { echo "usage: add-to-group <userId> <groupId>" >&2; exit 1; }
  require_int "$2"
  ensure_login
  gql 'mutation($u:String!,$g:Int!){ addUserToGroup(userId:$u, groupId:$g){ ok } }' \
    "$(jq -n --arg u "$1" --argjson g "$2" '{u:$u,g:$g}')" | jq '.data.addUserToGroup'
  publish os.groups Update "$1"
}

cmd_remove_from_group() {
  [[ $# -eq 2 ]] || { echo "usage: remove-from-group <userId> <groupId>" >&2; exit 1; }
  require_int "$2"
  ensure_login
  gql 'mutation($u:String!,$g:Int!){ removeUserFromGroup(userId:$u, groupId:$g){ ok } }' \
    "$(jq -n --arg u "$1" --argjson g "$2" '{u:$u,g:$g}')" | jq '.data.removeUserFromGroup'
  publish os.groups Update "$1"
}

# Resolves the id of the built-in lldap_admin group (admin role = membership).
admin_group_id() {
  local gid
  gid=$(gql 'query { groups { id displayName } }' \
    | jq -r '.data.groups[] | select(.displayName=="lldap_admin") | .id')
  [[ -n "$gid" && "$gid" != "null" ]] || { echo "lldap_admin group not found" >&2; exit 1; }
  echo "$gid"
}

cmd_make_admin() {
  [[ $# -eq 1 ]] || { echo "usage: make-admin <userId>" >&2; exit 1; }
  ensure_login
  cmd_add_to_group "$1" "$(admin_group_id)"
}

cmd_remove_admin() {
  [[ $# -eq 1 ]] || { echo "usage: remove-admin <userId>" >&2; exit 1; }
  ensure_login
  cmd_remove_from_group "$1" "$(admin_group_id)"
}

usage() {
  cat >&2 <<'EOF'
lldapctl.sh - CRUD helper for the local dev LLDAP

Usage: ./lldapctl.sh <command> [args]

Users:
  list-users
  get-user <id>
  create-user <id> [email] [displayName]   # email/displayName default off <id>
  delete-user <id>

Roles (admin = membership in the built-in lldap_admin group):
  make-admin <userId>
  remove-admin <userId>

Groups:
  list-groups
  create-group <name>
  delete-group <groupId>
  add-to-group <userId> <groupId>
  remove-from-group <userId> <groupId>

Each mutation also publishes an os.users/os.groups NATS trigger (best-effort).

Env: LLDAP_URL (default http://localhost:17170), ADMIN_USER (alice), ADMIN_PASS (password),
     EMAIL_DOMAIN (default example.com, for create-user's generated email),
     NATS_NETWORK (docker network, default lldap-dev),
     NATS_SERVER (default nats://nats:4222), NATS_USERNAME (lldap), NATS_PASSWORD (secret),
     NATS_BOX_IMAGE (default natsio/nats-box:latest)
EOF
}

main() {
  [[ $# -ge 1 ]] || { usage; exit 1; }
  local cmd="$1"; shift
  case "$cmd" in
    -h|--help|help)     usage;;
    list-users)         cmd_list_users "$@";;
    get-user)           cmd_get_user "$@";;
    create-user)        cmd_create_user "$@";;
    delete-user)        cmd_delete_user "$@";;
    make-admin)         cmd_make_admin "$@";;
    remove-admin)       cmd_remove_admin "$@";;
    list-groups)        cmd_list_groups "$@";;
    create-group)       cmd_create_group "$@";;
    delete-group)       cmd_delete_group "$@";;
    add-to-group)       cmd_add_to_group "$@";;
    remove-from-group)  cmd_remove_from_group "$@";;
    *) echo "unknown command: $cmd" >&2; usage; exit 1;;
  esac
}

main "$@"
