# Local dev stack

A persistent `lldap + nats` stack so an app you're building (e.g. `files`) can
connect to LLDAP and consume account events from its own `docker-compose`, with
data that survives restarts. (For the one-shot smoke test see [../go/test](../go/test).)

## Start

```bash
docker compose pull
docker compose up -d
```

On first boot LLDAP creates one admin user, **`alice`** / `password`. Add more
users with `lldapctl.sh` (below).

| What            | Address                 | Credentials          |
| --------------- | ----------------------- | -------------------- |
| Web / GraphQL   | http://localhost:17170  | `alice` / `password` |
| Read-only API   | http://localhost:17171  | none (network-gated) |
| LDAP            | `localhost:3890`        | bind as `alice`      |
| NATS            | `nats://localhost:4222` | `lldap` / `secret`   |

Notes:
- The admin is `alice`, not LLDAP's default `admin`: the compose sets
  `LLDAP_LDAP_USER_DN: alice`, so LLDAP bootstraps it as the admin (at least one
  admin is mandatory — see `server/src/main.rs`).
- The read-only port (`17171`, `GET /readonly/snapshot`) — the endpoint the SDK
  consumer reads — works out of the box: the default image is a temporary branch
  build (`beclab/lldap:go-sync-sdk-dev`, see `.github/workflows/dev-image.yml`)
  that includes it. Use the commented `build:` block only to test un-pushed local
  changes, or override the tag with `LLDAP_IMAGE=...`.
- Data lives in the `lldap_pgdata` volume (Postgres, since SQLite rejects the v12
  migration). `docker compose down` keeps it; `down -v` wipes it for a clean DB.

Reset to an empty DB (re-creates `alice` on next boot):

```bash
docker compose down -v
docker compose up -d
```

## Writing the consumer

The consumer reads the snapshot from LLDAP's unauthenticated read-only port
(`GET /readonly/snapshot` on `17171`) — no credentials; access is meant to be
gated by the network layer (e.g. a K8s NetworkPolicy). The default image already
exposes it (see Notes above).

Use the single `client` package; [../go/example/main.go](../go/example/main.go)
is the template. Write one idempotent `apply(ctx, client.Changes) error` (return
nil only when the whole batch applied — see the SDK README), call
`c.Init(ctx, dbUsers, dbGroups)` at startup and apply the result, then `c.Run`
with `OnChanges: apply`. `Run` consumes `os.users` / `os.groups` as reconcile
triggers; `User.IsAdmin()` reports `lldap_admin` membership.

Run the reference consumer on your host and watch it reconcile:

```bash
curl -s http://localhost:17171/readonly/snapshot | jq   # peek at the payload

cd ../go
LLDAP_URL=http://localhost:17171 \
NATS_URL=nats://localhost:4222 NATS_USERNAME=lldap NATS_PASSWORD=secret \
go run ./example
```

## CRUD helper: `lldapctl.sh`

Drives user/group changes via GraphQL and, after each mutation, publishes the
matching `os.users` / `os.groups` NATS trigger — **simulating app-service** (in
Olares app-service emits these; LLDAP itself does not). Needs only `curl`, `jq`,
and `docker`; the publish runs in a one-shot `nats-box` container and is
best-effort.

```bash
./lldapctl.sh create-user carol   # email/displayName auto-filled from the id
./lldapctl.sh make-admin carol
./lldapctl.sh remove-admin carol
./lldapctl.sh list-users
./lldapctl.sh delete-user carol
```

Env overrides: `LLDAP_URL`, `ADMIN_USER`, `ADMIN_PASS`, `EMAIL_DOMAIN`,
`NATS_NETWORK`, `NATS_SERVER`, `NATS_USERNAME`, `NATS_PASSWORD`, `NATS_BOX_IMAGE`.
Run `./lldapctl.sh help` for all commands. It can't set passwords (the image has
no set-password binary), but consumers only read, so test users don't need one.
