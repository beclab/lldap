package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// snapshotJSON is the read-only endpoint body: users/groups at the top level
// (the same fields GraphQL exposes, without the GraphQL `data` envelope).
const snapshotJSON = `{
  "users": [
    {
      "id": "alice",
      "email": "alice@example.com",
      "displayName": "Alice",
      "firstName": "Al",
      "lastName": "Ice",
      "creationDate": "2026-01-01T00:00:00Z",
      "uuid": "uuid-1",
      "groups": [{"displayName": "admin"}, {"displayName": "staff"}],
      "attributes": [{"name": "uidNumber", "value": ["1001"]}]
    }
  ],
  "groups": [
    {"id": 3, "displayName": "admin", "users": [{"id": "alice"}, {"id": "bob"}],
     "attributes": [{"name": "club", "value": ["chess"]}]}
  ]
}`

// newServer returns an httptest server serving the read-only snapshot endpoint.
func newServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/readonly/snapshot", handler)
	return httptest.NewServer(mux)
}

func TestSnapshotFlattening(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(snapshotJSON))
	})
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL})
	snap, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	if len(snap.Users) != 1 {
		t.Fatalf("want 1 user, got %d", len(snap.Users))
	}
	u := snap.Users[0]
	if u.ID != "alice" || u.Email != "alice@example.com" || u.UUID != "uuid-1" {
		t.Fatalf("scalar user fields wrong: %+v", u)
	}
	if len(u.Groups) != 2 || u.Groups[0] != "admin" || u.Groups[1] != "staff" {
		t.Fatalf("group displayNames not flattened: %+v", u.Groups)
	}
	if got := u.Attributes["uidNumber"]; len(got) != 1 || got[0] != "1001" {
		t.Fatalf("attributes not flattened: %+v", u.Attributes)
	}
	if len(snap.Groups) != 1 {
		t.Fatalf("want 1 group, got %d", len(snap.Groups))
	}
	g := snap.Groups[0]
	if g.ID != 3 || g.DisplayName != "admin" {
		t.Fatalf("group scalar fields wrong: %+v", g)
	}
	if len(g.Members) != 2 || g.Members[0] != "alice" || g.Members[1] != "bob" {
		t.Fatalf("group members not flattened: %+v", g.Members)
	}
	if got := g.Attributes["club"]; len(got) != 1 || got[0] != "chess" {
		t.Fatalf("group attributes not flattened: %+v", g.Attributes)
	}
}

func TestInitReturnsDiffAndSetsBaseline(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(snapshotJSON))
	})
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL})

	// The store already has alice exactly as LLDAP has her, so Init should only
	// report the admin group (id 3) as new, with no user changes.
	existing := User{
		ID:          "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		FirstName:   "Al",
		LastName:    "Ice",
		Groups:      []string{"admin", "staff"},
		Attributes:  map[string][]string{"uidNumber": {"1001"}},
	}
	changes, err := c.Init(context.Background(), []User{existing}, nil)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if len(changes.UsersAdded) != 0 || len(changes.UsersUpdated) != 0 || len(changes.UsersRemoved) != 0 {
		t.Fatalf("expected no user changes, got %+v", changes)
	}
	if len(changes.GroupsAdded) != 1 || changes.GroupsAdded[0].ID != 3 {
		t.Fatalf("expected admin group added, got %+v", changes.GroupsAdded)
	}

	c.mu.Lock()
	baseline := c.baseline
	c.mu.Unlock()
	if len(baseline.Users) != 1 || len(baseline.Groups) != 1 {
		t.Fatalf("baseline not recorded: %+v", baseline)
	}
}

func TestSnapshotHTTPErrorReturned(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("nope"))
	})
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL})
	if _, err := c.Snapshot(context.Background()); err == nil {
		t.Fatal("expected error from non-200 response")
	}
}
