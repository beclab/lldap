#!/usr/bin/env bash
#
# Local end-to-end smoke test for the LLDAP Go SDK.
#
# LLDAP itself does not publish events; in Olares app-service does. So this test
# mutates LLDAP via the admin GraphQL API and, like lldapctl/app-service,
# publishes the matching os.users / os.groups NATS trigger itself (via `nats pub`
# in a nats-box container). The SDK example consumes the unauthenticated
# read-only port; the test asserts its reconcile output reflects each change.
#
# Requirements: docker (with compose v2), curl, and Go on PATH. The first run is
# slow because it compiles the LLDAP server image from source.
#
# Usage: ./smoke_test.sh

set -euo pipefail
cd "$(dirname "$0")"

# LLDAP_URL is the admin GraphQL API the harness mutates (acting as app-service);
# READONLY_URL is the unauthenticated read-only port the SDK example consumes.
LLDAP_URL=${LLDAP_URL:-http://localhost:17170}
READONLY_URL=${READONLY_URL:-http://localhost:17171}
NATS_URL=${NATS_URL:-nats://localhost:4222}
ADMIN_USER=${ADMIN_USER:-admin}
ADMIN_PASS=${ADMIN_PASS:-password}
USER_ID="smoke-$(date +%s)"
LOG="$(pwd)/example.log"
EXAMPLE_PID=""

cleanup() {
  [[ -n "$EXAMPLE_PID" ]] && kill "$EXAMPLE_PID" 2>/dev/null || true
  docker compose down -v >/dev/null 2>&1 || true
  rm -f "$LOG"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  echo "--- example.log ---" >&2
  cat "$LOG" >&2 2>/dev/null || true
  exit 1
}

token=""
gql() {
  curl -fsS -X POST "$LLDAP_URL/api/graphql" \
    -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' \
    -d "$1"
}

# pub SUBJECT [TOPIC NAME] - emit an os.* reconcile trigger, mimicking
# app-service. Only SUBJECT matters; the SDK treats events as triggers, so the
# payload (and any TOPIC/NAME args, kept for call-site readability) is ignored.
# Runs `nats pub` in a nats-box container on the compose network.
pub() {
  docker run --rm --network lldap-smoke natsio/nats-box:latest \
    nats pub --server nats://nats:4222 --user lldap --password secret \
    "$1" '{"topic":"trigger"}' >/dev/null 2>&1 || fail "failed to publish to $1"
}

# wait_for_log NEEDLE TIMEOUT_SECONDS
wait_for_log() {
  local needle="$1" timeout="$2"
  for _ in $(seq 1 "$timeout"); do
    grep -q -- "$needle" "$LOG" 2>/dev/null && return 0
    sleep 1
  done
  return 1
}

echo "==> Bringing up nats + lldap (building lldap from source)"
docker compose up -d --build

echo "==> Waiting for lldap to accept logins"
for _ in $(seq 1 90); do
  token=$(curl -fsS -X POST "$LLDAP_URL/auth/simple/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" 2>/dev/null \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p' || true)
  [[ -n "$token" ]] && break
  sleep 2
done
[[ -n "$token" ]] || fail "lldap did not become ready"
echo "    got admin token"

echo "==> Starting SDK example consumer"
: > "$LOG"
(
  cd ..
  LLDAP_URL="$READONLY_URL" \
  NATS_URL="$NATS_URL" \
  NATS_USERNAME=lldap \
  NATS_PASSWORD=secret \
  DURABLE=smoke \
  RESYNC=15s \
  go run ./example
) >"$LOG" 2>&1 &
EXAMPLE_PID=$!

# The example does its blocking init snapshot and creates the stream/consumer.
wait_for_log "init:" 30 || fail "example never produced an initial snapshot"
echo "    example is consuming"

echo "==> Creating user $USER_ID"
gql "{\"query\":\"mutation { createUser(user: {id: \\\"$USER_ID\\\", email: \\\"$USER_ID@example.com\\\", displayName: \\\"Smoke\\\"}) { id } }\"}" >/dev/null
pub os.users Create "$USER_ID"
wait_for_log "user added: $USER_ID" 30 || fail "created user did not produce a 'user added' change"
echo "    PASS: user creation observed"

echo "==> Updating the user and asserting a 'user updated' change fires"
gql "{\"query\":\"mutation { updateUser(user: {id: \\\"$USER_ID\\\", displayName: \\\"Smoke Renamed\\\"}) { ok } }\"}" >/dev/null
pub os.users Update "$USER_ID"
wait_for_log "user updated: $USER_ID" 30 || fail "updated user did not produce a 'user updated' change"
echo "    PASS: user update observed"

echo "==> Creating a group and asserting a 'group added' change fires"
group_id=$(gql "{\"query\":\"mutation { createGroup(name: \\\"smoke-group\\\") { id } }\"}" \
  | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
[[ -n "$group_id" ]] || fail "could not create group"
pub os.groups Create smoke-group
wait_for_log "group added: smoke-group (id=$group_id)" 30 || fail "created group did not produce a 'group added' change"
echo "    PASS: group creation observed (group id=$group_id)"

echo "==> Renaming the group and asserting a 'group updated' change fires"
gql "{\"query\":\"mutation { updateGroup(group: {id: $group_id, displayName: \\\"smoke-group-renamed\\\"}) { ok } }\"}" >/dev/null
pub os.groups Update smoke-group-renamed
wait_for_log "group updated: smoke-group-renamed (id=$group_id)" 30 || fail "renamed group did not produce a 'group updated' change"
echo "    PASS: group update observed"

echo "==> Adding the user to the group and asserting a 'group member added' change fires"
gql "{\"query\":\"mutation { addUserToGroup(userId: \\\"$USER_ID\\\", groupId: $group_id) { ok } }\"}" >/dev/null
pub os.groups Update "$USER_ID"
wait_for_log "group member added: smoke-group-renamed -> $USER_ID" 30 || fail "group membership did not produce a 'group member added' change"
echo "    PASS: group membership observed"

echo "==> Making the user an admin and asserting an 'admin granted' change fires"
admin_gid=$(gql "{\"query\":\"query { groups { id displayName } }\"}" \
  | sed -n 's/.*"id":\([0-9]*\),"displayName":"lldap_admin".*/\1/p')
[[ -n "$admin_gid" ]] || fail "could not resolve lldap_admin group id"
gql "{\"query\":\"mutation { addUserToGroup(userId: \\\"$USER_ID\\\", groupId: $admin_gid) { ok } }\"}" >/dev/null
pub os.groups Update "$USER_ID"
wait_for_log "admin granted: $USER_ID" 30 || fail "make-admin did not produce an 'admin granted' change"
echo "    PASS: admin grant observed"

echo "==> Deleting the user and asserting a 'user removed' change fires"
gql "{\"query\":\"mutation { deleteUser(userId: \\\"$USER_ID\\\") { ok } }\"}" >/dev/null
pub os.users Delete "$USER_ID"
wait_for_log "user removed: $USER_ID" 30 || fail "deleted user did not produce a 'user removed' change"
echo "    PASS: user deletion observed"

echo "==> Deleting the group and asserting a 'group removed' change fires"
gql "{\"query\":\"mutation { deleteGroup(groupId: $group_id) { ok } }\"}" >/dev/null
pub os.groups Delete smoke-group-renamed
wait_for_log "group removed: smoke-group-renamed (id=$group_id)" 30 || fail "deleted group did not produce a 'group removed' change"
echo "    PASS: group deletion observed"

echo "==> ALL SMOKE CHECKS PASSED"
