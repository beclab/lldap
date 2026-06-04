package client

import "testing"

func mkUser(id, email string) User {
	return User{ID: id, Email: email, DisplayName: id}
}

func mkSnap(users []User, groups []Group) Snapshot {
	return Snapshot{Users: users, Groups: groups}
}

func TestComputeChangesUsers(t *testing.T) {
	alice := mkUser("alice", "alice@example.com")
	bob := mkUser("bob", "bob@example.com")

	prev := mkSnap([]User{alice}, nil)
	next := mkSnap([]User{
		{ID: "alice", Email: "alice@new.com", DisplayName: "alice"}, // updated
		bob, // added
	}, nil)

	c := computeChanges(prev, next)

	if len(c.UsersAdded) != 1 || c.UsersAdded[0].ID != "bob" {
		t.Fatalf("expected bob added, got %+v", c.UsersAdded)
	}
	if len(c.UsersUpdated) != 1 || c.UsersUpdated[0].New.Email != "alice@new.com" {
		t.Fatalf("expected alice updated, got %+v", c.UsersUpdated)
	}
	if len(c.UsersRemoved) != 0 {
		t.Fatalf("expected no removals, got %+v", c.UsersRemoved)
	}
}

func TestComputeChangesUserRemoved(t *testing.T) {
	c := computeChanges(
		mkSnap([]User{mkUser("alice", "a@x"), mkUser("bob", "b@x")}, nil),
		mkSnap([]User{mkUser("alice", "a@x")}, nil),
	)
	if len(c.UsersRemoved) != 1 || c.UsersRemoved[0].ID != "bob" {
		t.Fatalf("expected bob removed, got %+v", c.UsersRemoved)
	}
	if len(c.UsersAdded) != 0 || len(c.UsersUpdated) != 0 {
		t.Fatalf("unexpected add/update: %+v", c)
	}
}

func TestComputeChangesUserAttributesUpdate(t *testing.T) {
	a := mkUser("alice", "a@x")
	a.Attributes = map[string][]string{"uidNumber": {"1001"}}
	b := mkUser("alice", "a@x")
	b.Attributes = map[string][]string{"uidNumber": {"1002"}}

	c := computeChanges(mkSnap([]User{a}, nil), mkSnap([]User{b}, nil))
	if len(c.UsersUpdated) != 1 {
		t.Fatalf("expected attribute change to be an update, got %+v", c.UsersUpdated)
	}
}

func TestComputeChangesGroupOnlyChangeIsNotUserUpdate(t *testing.T) {
	// Same user fields, only the User.Groups slice differs: must NOT be a user
	// update (membership surfaces via group member callbacks instead).
	a := mkUser("alice", "a@x")
	a.Groups = []string{"staff"}
	b := mkUser("alice", "a@x")
	b.Groups = []string{"staff", "admin"}

	c := computeChanges(mkSnap([]User{a}, nil), mkSnap([]User{b}, nil))
	if len(c.UsersUpdated) != 0 {
		t.Fatalf("group-only change must not be a user update, got %+v", c.UsersUpdated)
	}
}

func TestComputeChangesGroups(t *testing.T) {
	prev := mkSnap(nil, []Group{{ID: 1, DisplayName: "staff"}})
	next := mkSnap(nil, []Group{
		{ID: 1, DisplayName: "staff-renamed"}, // updated
		{ID: 2, DisplayName: "admin"},         // added
	})

	c := computeChanges(prev, next)
	if len(c.GroupsAdded) != 1 || c.GroupsAdded[0].ID != 2 {
		t.Fatalf("expected group 2 added, got %+v", c.GroupsAdded)
	}
	if len(c.GroupsUpdated) != 1 || c.GroupsUpdated[0].New.DisplayName != "staff-renamed" {
		t.Fatalf("expected group 1 renamed, got %+v", c.GroupsUpdated)
	}
}

func TestComputeChangesGroupAttributesUpdate(t *testing.T) {
	prev := mkSnap(nil, []Group{{ID: 1, DisplayName: "staff", Attributes: map[string][]string{"club": {"a"}}}})
	next := mkSnap(nil, []Group{{ID: 1, DisplayName: "staff", Attributes: map[string][]string{"club": {"b"}}}})

	c := computeChanges(prev, next)
	if len(c.GroupsUpdated) != 1 {
		t.Fatalf("expected group attribute change to be an update, got %+v", c.GroupsUpdated)
	}
}

func TestComputeChangesGroupRemoved(t *testing.T) {
	c := computeChanges(
		mkSnap(nil, []Group{{ID: 1, DisplayName: "staff"}}),
		mkSnap(nil, nil),
	)
	if len(c.GroupsRemoved) != 1 || c.GroupsRemoved[0].ID != 1 {
		t.Fatalf("expected group 1 removed, got %+v", c.GroupsRemoved)
	}
}

func TestComputeChangesMembership(t *testing.T) {
	prev := mkSnap(nil, []Group{{ID: 1, DisplayName: "staff", Members: []string{"alice"}}})
	next := mkSnap(nil, []Group{{ID: 1, DisplayName: "staff", Members: []string{"bob"}}})

	c := computeChanges(prev, next)
	if len(c.MembersAdded) != 1 || c.MembersAdded[0].UserID != "bob" || c.MembersAdded[0].Group.ID != 1 {
		t.Fatalf("expected bob added to group 1, got %+v", c.MembersAdded)
	}
	if len(c.MembersRemoved) != 1 || c.MembersRemoved[0].UserID != "alice" {
		t.Fatalf("expected alice removed from group 1, got %+v", c.MembersRemoved)
	}
	if len(c.GroupsUpdated) != 0 {
		t.Fatalf("membership change must not be a group update, got %+v", c.GroupsUpdated)
	}
}

func TestComputeChangesNoChange(t *testing.T) {
	s := mkSnap(
		[]User{mkUser("alice", "a@x")},
		[]Group{{ID: 1, DisplayName: "staff", Members: []string{"alice"}}},
	)
	if c := computeChanges(s, s); !c.IsEmpty() {
		t.Fatalf("expected no changes, got %+v", c)
	}
}

func TestComputeChangesBaselineEmptyReportsAllAdded(t *testing.T) {
	next := mkSnap(
		[]User{mkUser("alice", "a@x")},
		[]Group{{ID: 1, DisplayName: "staff"}},
	)
	c := computeChanges(Snapshot{}, next)
	if len(c.UsersAdded) != 1 || len(c.GroupsAdded) != 1 {
		t.Fatalf("empty baseline should report everything as added, got %+v", c)
	}
}

func TestComputeChangesAddedGroupReportsMembers(t *testing.T) {
	// A brand-new group with members must surface those members via
	// MembersAdded, so a consumer wiring only the member callbacks sees them.
	prev := mkSnap(nil, nil)
	next := mkSnap(nil, []Group{{ID: 1, DisplayName: "staff", Members: []string{"alice", "bob"}}})

	c := computeChanges(prev, next)
	if len(c.GroupsAdded) != 1 {
		t.Fatalf("expected group added, got %+v", c.GroupsAdded)
	}
	if len(c.MembersAdded) != 2 ||
		c.MembersAdded[0].UserID != "alice" || c.MembersAdded[1].UserID != "bob" {
		t.Fatalf("expected alice+bob memberships, got %+v", c.MembersAdded)
	}
}

func TestComputeChangesRemovedGroupReportsMembers(t *testing.T) {
	prev := mkSnap(nil, []Group{{ID: 1, DisplayName: "staff", Members: []string{"alice", "bob"}}})
	next := mkSnap(nil, nil)

	c := computeChanges(prev, next)
	if len(c.GroupsRemoved) != 1 {
		t.Fatalf("expected group removed, got %+v", c.GroupsRemoved)
	}
	if len(c.MembersRemoved) != 2 ||
		c.MembersRemoved[0].UserID != "alice" || c.MembersRemoved[1].UserID != "bob" {
		t.Fatalf("expected alice+bob memberships removed, got %+v", c.MembersRemoved)
	}
}
