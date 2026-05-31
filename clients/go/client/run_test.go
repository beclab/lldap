package client

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"testing"
)

var quietLogger = log.New(io.Discard, "", 0)

func newClientServingSnapshot(t *testing.T, body string) *Client {
	t.Helper()
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	t.Cleanup(srv.Close)
	return New(Config{BaseURL: srv.URL})
}

// newClientFailingSnapshot returns a client whose read-only endpoint always
// responds with an error status, so Snapshot fails.
func newClientFailingSnapshot(t *testing.T) *Client {
	t.Helper()
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	t.Cleanup(srv.Close)
	return New(Config{BaseURL: srv.URL})
}

func TestRunValidation(t *testing.T) {
	c := New(Config{BaseURL: "http://127.0.0.1:1"})
	noop := func(context.Context, Changes) error { return nil }

	// Missing OnChanges and missing Durable must both fail fast, before any
	// NATS connection is attempted.
	if err := c.Run(context.Background(), Options{Durable: "app"}); err == nil {
		t.Fatal("expected error when OnChanges is nil")
	}
	if err := c.Run(context.Background(), Options{OnChanges: noop}); err == nil {
		t.Fatal("expected error when Durable is empty")
	}
}

func TestReconcileAdvancesOnSuccess(t *testing.T) {
	c := newClientServingSnapshot(t, snapshotJSON)

	called := 0
	next := c.reconcile(context.Background(), Snapshot{}, func(context.Context, Changes) error {
		called++
		return nil
	}, quietLogger)

	if called != 1 {
		t.Fatalf("onChanges should run once, got %d", called)
	}
	if len(next.Users) != 1 || len(next.Groups) != 1 {
		t.Fatalf("baseline should advance to the fetched snapshot, got %+v", next)
	}
}

func TestReconcileKeepsBaselineOnHandlerError(t *testing.T) {
	c := newClientServingSnapshot(t, snapshotJSON)

	got := c.reconcile(context.Background(), Snapshot{}, func(context.Context, Changes) error {
		return errors.New("apply failed")
	}, quietLogger)

	if len(got.Users) != 0 || len(got.Groups) != 0 {
		t.Fatalf("baseline must stay at prev when the handler fails, got %+v", got)
	}
}

func TestReconcileSkipsHandlerOnEmptyDiff(t *testing.T) {
	c := newClientServingSnapshot(t, snapshotJSON)

	// First reconcile from empty establishes the baseline.
	base := c.reconcile(context.Background(), Snapshot{}, func(context.Context, Changes) error { return nil }, quietLogger)

	called := 0
	got := c.reconcile(context.Background(), base, func(context.Context, Changes) error {
		called++
		return nil
	}, quietLogger)

	if called != 0 {
		t.Fatalf("onChanges must not run on an empty diff, got %d calls", called)
	}
	if len(got.Users) != 1 || len(got.Groups) != 1 {
		t.Fatalf("baseline should still advance on an empty diff, got %+v", got)
	}
}

func TestReconcileKeepsBaselineOnSnapshotError(t *testing.T) {
	c := newClientFailingSnapshot(t)

	prev := Snapshot{Users: []User{mkUser("keep", "k@x")}}
	called := 0
	got := c.reconcile(context.Background(), prev, func(context.Context, Changes) error {
		called++
		return nil
	}, quietLogger)

	if called != 0 {
		t.Fatalf("onChanges must not run when the snapshot fetch fails, got %d", called)
	}
	if len(got.Users) != 1 || got.Users[0].ID != "keep" {
		t.Fatalf("baseline must stay at prev on snapshot error, got %+v", got)
	}
}
