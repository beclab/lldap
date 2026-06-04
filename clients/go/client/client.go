// Package client is the LLDAP Go SDK. It fetches a full account snapshot for
// reconciliation and (via Run) consumes Olares' os.users / os.groups NATS
// JetStream events as reconcile triggers, dispatching the diffs to the
// OnChanges handler. The NATS conventions live in events.go.
//
// The snapshot is read from LLDAP's unauthenticated read-only port
// (GET /readonly/snapshot): no login, no Authorization header. Access control
// is expected to be enforced by the network layer (e.g. a K8s NetworkPolicy),
// and the port must be enabled on the server (LLDAP_HTTP_READONLY_PORT).
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config configures a Client.
type Config struct {
	// BaseURL is LLDAP's read-only HTTP base, e.g. "http://lldap:17171". It must
	// point at the unauthenticated read-only port (LLDAP_HTTP_READONLY_PORT).
	BaseURL string
	// HTTPClient is optional; a sensible default is used when nil.
	HTTPClient *http.Client
}

// Client talks to a single LLDAP instance.
//
// Snapshot is safe to call from multiple goroutines, but Init/Run drive one
// consumer loop: a Client records a single baseline (Init) that Run reconciles
// against, so use one Client instance per consumer loop and do not run Run more
// than once concurrently on the same Client.
type Client struct {
	cfg  Config
	http *http.Client

	mu          sync.Mutex
	baseline    Snapshot
	initialized bool
}

// Init does the blocking startup reconcile: it fetches a full snapshot, diffs
// it against the state the consumer already has (users/groups loaded from its
// own store), and returns the Changes to apply. It also records the fetched
// snapshot as the baseline that Run diffs its first reconcile against, so
// changes that happen between Init and Run are delivered as Handler callbacks.
//
// Pass nil/empty slices when the consumer's store starts empty; the entire
// current state is then returned as additions.
func (c *Client) Init(ctx context.Context, users []User, groups []Group) (Changes, error) {
	snap, err := c.Snapshot(ctx)
	if err != nil {
		return Changes{}, err
	}
	changes := computeChanges(Snapshot{Users: users, Groups: groups}, snap)
	c.mu.Lock()
	c.baseline = snap
	c.initialized = true
	c.mu.Unlock()
	return changes, nil
}

// New creates a Client.
func New(cfg Config) *Client {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &Client{cfg: cfg, http: httpClient}
}

// snapshotData is the read-only endpoint's JSON body: the same users/groups
// fields the GraphQL snapshot exposes.
type snapshotData struct {
	Users []struct {
		ID           string `json:"id"`
		Email        string `json:"email"`
		DisplayName  string `json:"displayName"`
		FirstName    string `json:"firstName"`
		LastName     string `json:"lastName"`
		CreationDate string `json:"creationDate"`
		UUID         string `json:"uuid"`
		Groups       []struct {
			DisplayName string `json:"displayName"`
		} `json:"groups"`
		Attributes []struct {
			Name  string   `json:"name"`
			Value []string `json:"value"`
		} `json:"attributes"`
	} `json:"users"`
	Groups []struct {
		ID          int    `json:"id"`
		DisplayName string `json:"displayName"`
		Users       []struct {
			ID string `json:"id"`
		} `json:"users"`
		Attributes []struct {
			Name  string   `json:"name"`
			Value []string `json:"value"`
		} `json:"attributes"`
	} `json:"groups"`
}

// Snapshot fetches all users and groups in a single GET against the read-only
// port. No credentials are sent.
func (c *Client) Snapshot(ctx context.Context) (Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/readonly/snapshot", nil)
	if err != nil {
		return Snapshot{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Snapshot{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Snapshot{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Snapshot{}, fmt.Errorf("lldap readonly http %d: %s", resp.StatusCode, string(body))
	}
	var data snapshotData
	if err := json.Unmarshal(body, &data); err != nil {
		return Snapshot{}, err
	}
	return buildSnapshot(data), nil
}

func buildSnapshot(resp snapshotData) Snapshot {
	snap := Snapshot{
		Users:  make([]User, 0, len(resp.Users)),
		Groups: make([]Group, 0, len(resp.Groups)),
	}
	for _, u := range resp.Users {
		groups := make([]string, 0, len(u.Groups))
		for _, g := range u.Groups {
			groups = append(groups, g.DisplayName)
		}
		attrs := make(map[string][]string, len(u.Attributes))
		for _, a := range u.Attributes {
			attrs[a.Name] = a.Value
		}
		snap.Users = append(snap.Users, User{
			ID:           u.ID,
			Email:        u.Email,
			DisplayName:  u.DisplayName,
			FirstName:    u.FirstName,
			LastName:     u.LastName,
			CreationDate: u.CreationDate,
			UUID:         u.UUID,
			Groups:       groups,
			Attributes:   attrs,
		})
	}
	for _, g := range resp.Groups {
		members := make([]string, 0, len(g.Users))
		for _, m := range g.Users {
			members = append(members, m.ID)
		}
		attrs := make(map[string][]string, len(g.Attributes))
		for _, a := range g.Attributes {
			attrs[a.Name] = a.Value
		}
		snap.Groups = append(snap.Groups, Group{
			ID:          g.ID,
			DisplayName: g.DisplayName,
			Members:     members,
			Attributes:  attrs,
		})
	}
	return snap
}
