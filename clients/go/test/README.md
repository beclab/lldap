# Local smoke test

End-to-end verification of the LLDAP Go SDK against a real LLDAP + NATS stack.

## What it does

1. `docker compose up -d --build` starts:
   - `nats` with JetStream enabled (`-js`) and user/pass auth.
   - `lldap` built from this repo, with the unauthenticated read-only port
     (`17171`) enabled and `NATS_*` env vars pointed at the `nats` service.
2. Runs the SDK [example](../example) as a consumer, reading the snapshot from
   the read-only port (`17171`, no credentials).
3. Drives changes via the admin GraphQL API (`createUser`, `createGroup`,
   `addUserToGroup`, `deleteUser`) and publishes the matching `os.*` NATS
   triggers, then asserts the example's reconcile output reflects each change.

## Run

```bash
./smoke_test.sh
```

Requirements: `docker` (compose v2), `curl`, and `go` on PATH. The first run is
slow because it compiles the LLDAP server image from source (the read-only port
ships only in this checkout, not in any published image).

## Notes

- The read-only port is what the SDK consumes, so this test must build LLDAP from
  source; a published image without it won't work.
- Ports 17170 (HTTP/GraphQL), 17171 (read-only), 3890 (LDAP) and 4222 (NATS) are
  published to the host; make sure they are free.
