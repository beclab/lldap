// Command example is a runnable reference for consuming the LLDAP Go SDK.
//
// It mirrors what an app like `files` would do instead of watching a user CRD:
//
//  1. Startup (blocking): client.Init reconciles the current LLDAP state
//     against the app's own store and returns the changes to apply. Here we
//     start from an empty store; a real app would load its store first.
//  2. Streaming: client.Run consumes Olares' os.users / os.groups NATS events
//     as triggers (the payload is never decoded) and delivers each subsequent
//     diff to the same OnChanges handler (where files would incrementally
//     rebuild its Samba/POSIX state).
//
// Both steps speak the same client.Changes type, so the consumer writes a
// single apply function and reuses it for startup and streaming.
//
// Admin vs normal is derived from membership in client.AdminGroup
// (lldap_admin). The owner cannot yet be distinguished from an admin: that
// distinction lives only in the K8s User CR and is not synced to LLDAP.
//
// Configure via environment variables:
//
//	LLDAP_URL       LLDAP read-only port (default http://localhost:17171)
//	NATS_URL        (default nats://localhost:4222)
//	NATS_USERNAME, NATS_PASSWORD (optional)
//	DURABLE         (default example-app)
//	RESYNC          (default 30s)
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/beclab/lldap/clients/go/client"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// apply applies one batch of changes to the consumer's store. A real app would
// create/remove accounts here (e.g. files rebuilding Samba/POSIX state).
//
// Contract: return nil ONLY when the whole batch is applied. Returning an error
// makes the SDK keep its baseline and re-deliver the same (and newer) changes
// next reconcile, so this function MUST be idempotent — applying the same
// Changes twice must be safe. This example only logs, so it always succeeds.
func apply(_ context.Context, ch client.Changes) error {
	for _, u := range ch.UsersAdded {
		// IsAdmin (membership in client.AdminGroup) is how an app decides
		// whether to provision admin-only resources. Note owner and admin both
		// report true; the owner cannot be told apart here.
		if u.IsAdmin() {
			log.Printf("admin user added: %s (would provision with admin privileges)", u.ID)
		} else {
			log.Printf("user added: %s", u.ID)
		}
	}
	for _, p := range ch.UsersUpdated {
		// A user's own fields changed. Re-check IsAdmin so the app keeps the
		// account's privileges in sync.
		log.Printf("user updated: %s (admin=%t)", p.New.ID, p.New.IsAdmin())
	}
	for _, g := range ch.GroupsAdded {
		log.Printf("group added: %s (id=%d, attrs=%v)", g.DisplayName, g.ID, g.Attributes)
	}
	for _, p := range ch.GroupsUpdated {
		log.Printf("group updated: %s (id=%d, attrs=%v)", p.New.DisplayName, p.New.ID, p.New.Attributes)
	}
	for _, m := range ch.MembersAdded {
		log.Printf("group member added: %s -> %s", m.Group.DisplayName, m.UserID)
		if m.Group.DisplayName == client.AdminGroup {
			log.Printf("admin granted: %s", m.UserID)
		}
	}
	for _, m := range ch.MembersRemoved {
		log.Printf("group member removed: %s -> %s", m.Group.DisplayName, m.UserID)
	}
	for _, g := range ch.GroupsRemoved {
		log.Printf("group removed: %s (id=%d)", g.DisplayName, g.ID)
	}
	for _, u := range ch.UsersRemoved {
		log.Printf("user removed: %s", u.ID)
	}
	return nil
}

func main() {
	resync, err := time.ParseDuration(env("RESYNC", "30s"))
	if err != nil {
		log.Fatalf("invalid RESYNC: %v", err)
	}

	baseURL := env("LLDAP_URL", "http://localhost:17171")
	c := client.New(client.Config{
		BaseURL: baseURL,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Step 1: blocking startup reconcile. A real app passes its store's current
	// users/groups; Init returns the diff to apply. Here the store starts empty,
	// so everything comes back as additions.
	changes, err := c.Init(ctx, nil, nil)
	if err != nil {
		log.Fatalf("example: init: %v", err)
	}
	log.Printf("init: %d users, %d groups", len(changes.UsersAdded), len(changes.GroupsAdded))
	if err := apply(ctx, changes); err != nil {
		log.Fatalf("example: apply init: %v", err)
	}

	// Step 2: stream subsequent changes through the same apply function.
	opts := client.Options{
		NATSURL:        env("NATS_URL", "nats://localhost:4222"),
		NATSUser:       os.Getenv("NATS_USERNAME"),
		NATSPass:       os.Getenv("NATS_PASSWORD"),
		Durable:        env("DURABLE", "example-app"),
		ResyncInterval: resync,
		OnChanges:      apply,
	}

	log.Printf("example: starting, lldap=%s nats=%s", baseURL, opts.NATSURL)
	if err := c.Run(ctx, opts); err != nil && err != context.Canceled {
		log.Fatalf("example: %v", err)
	}
}
