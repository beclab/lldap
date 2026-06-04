# LLDAP Go SDK

A small Go SDK for syncing accounts from LLDAP into platform components
(e.g. a file server that provisions Samba/POSIX accounts), replacing the need
to watch a Kubernetes User CRD.

It implements the "event trigger + full snapshot + idempotent reconcile" model.
The whole SDK lives in one package, `client`:

- a `Client` that reads the snapshot from LLDAP's **unauthenticated read-only
  port** (`GET /readonly/snapshot`) — no login, no credentials,
- a blocking `Init` for the startup reconcile,
- a `Run` loop that consumes Olares' `os.users` / `os.groups` NATS JetStream
  events as triggers, diffs each new snapshot against the previous one, and
  delivers the `Changes` to a single `OnChanges` handler, plus a periodic
  safety-net resync.

The read-only port carries no auth: access must be enforced by the network layer
(e.g. a K8s NetworkPolicy). The server must have it enabled
(`LLDAP_HTTP_READONLY_PORT`), and `BaseURL` must point at it.

In Olares these events are published by app-service today (LLDAP itself does not
emit them). One current limitation: the owner cannot be distinguished from an
admin, since both map to the `lldap_admin` group and the role lives only in the
K8s User CR.

Both `Init` (return value) and `Run` (`OnChanges`) speak the same `Changes`
type, so you write one apply function and reuse it for startup and streaming.

## Usage

Call `Init` with your store's current users/groups to do the blocking startup
reconcile; it returns the `Changes` to apply and records the baseline. Then call
`Run`, handing the same apply function to `OnChanges`:

```go
c := client.New(client.Config{
    BaseURL: "http://lldap:17171", // LLDAP's read-only port
})

// apply applies one batch of changes to your store (create/remove accounts,
// u.Attributes["uidNumber"], ...). Return nil ONLY when the whole batch is
// applied; returning an error makes Run re-deliver the same (and newer) changes
// next reconcile, so apply MUST be idempotent.
apply := func(ctx context.Context, ch client.Changes) error {
    for _, u := range ch.UsersAdded { /* ... */ }
    for _, m := range ch.MembersRemoved { /* ... */ }
    // ... UsersUpdated / UsersRemoved / Groups* / MembersAdded ...
    return nil
}

// 1. Startup: reconcile LLDAP against your own store. Pass the users/groups you
//    already have (nil/empty when your store starts empty); Init returns the
//    changes to apply and records the baseline.
changes, err := c.Init(ctx, dbUsers, dbGroups)
if err != nil { /* ... */ }
if err := apply(ctx, changes); err != nil { /* ... */ }

// 2. Stream subsequent changes through the same apply function.
err = c.Run(ctx, client.Options{
    NATSURL:        "nats://nats.os-platform:4222",
    NATSUser:       "lldap",
    NATSPass:       "secret",
    Durable:        "files-samba",
    ResyncInterval: 5 * time.Minute,
    OnChanges:      apply,
})
```

## Notes

- Events are lightweight triggers (the payload is never decoded); the read-only
  snapshot is the source of truth. `Run` consumes `os.users`/`os.groups` on the
  `os-stream` stream by default; override via `Options.StreamName`/`Subjects`.
- `Options.Durable` is required and must be unique per consuming app: two apps
  sharing a durable name on the same stream would split each other's triggers.
- `User.IsAdmin()` reports membership in the built-in `lldap_admin` group. In
  Olares both owner and admin map to that group, so the owner cannot yet be
  distinguished (it lives only in the K8s User CR, not LLDAP).
- `OnChanges` must return nil only when the whole batch is applied. Returning an
  error keeps the baseline and re-delivers the same (and newer) `Changes` on the
  next reconcile, so the handler **must be idempotent** (delivery is at-least-once
  and failed batches are retried).
- A safe apply order within a batch: create users, then groups, then memberships;
  remove memberships, then groups, then users. Updates can go anywhere.
- A user's group membership change surfaces in `MembersAdded/MembersRemoved`, not
  `UsersUpdated` (which only covers the user's own fields/attributes). The members
  of a newly added/removed group appear there too, so a batch is self-contained.
- The first `Run` reconcile diffs against the baseline recorded by `Init`, so
  changes that happened during startup are delivered too. Without a prior `Init`,
  the entire current state is reported as additions.
- POSIX `uidNumber`/`gidNumber` are expected as LLDAP user attributes and are
  surfaced in `User.Attributes`.

See [example](example) for a runnable program and [test](test) for a local
docker-compose smoke test.
