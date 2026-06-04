package client

// This file holds the SDK's data model: the flattened LLDAP entities (User,
// Group, Snapshot) and the diff types delivered to consumers (Changes and its
// parts). The client transport lives in client.go and the diff logic in diff.go.

// AdminGroup is the built-in LLDAP group whose members are administrators.
//
// In Olares both the owner and admins are added to this group, so the SDK can
// tell an admin from a normal user but cannot yet identify the owner: the
// owner/admin/normal distinction lives only in the K8s User CR annotation
// bytetrade.io/owner-role and is never synced to LLDAP.
const AdminGroup = "lldap_admin"

// User is a flattened view of an LLDAP user for reconciliation.
type User struct {
	ID           string
	Email        string
	DisplayName  string
	FirstName    string
	LastName     string
	CreationDate string
	UUID         string
	Groups       []string
	// Attributes holds user-defined attributes (e.g. uidNumber/gidNumber).
	Attributes map[string][]string
}

// IsAdmin reports whether the user is an administrator, i.e. a member of the
// built-in AdminGroup. Note this is true for both Olares owners and admins;
// owners cannot currently be distinguished (see AdminGroup).
//
// Admin status comes from group membership, not a user field, so granting or
// revoking it surfaces as MembersAdded/MembersRemoved on AdminGroup, NOT as a
// UsersUpdated entry. Consumers that care about admin changes must re-check
// IsAdmin() from the member callbacks, not only on user updates.
func (u User) IsAdmin() bool {
	for _, g := range u.Groups {
		if g == AdminGroup {
			return true
		}
	}
	return false
}

// Group is a flattened view of an LLDAP group.
type Group struct {
	ID          int
	DisplayName string
	Members     []string
	// Attributes holds group-defined attributes (the group analogue of
	// User.Attributes).
	Attributes map[string][]string
}

// Snapshot is a point-in-time view of all users and groups.
type Snapshot struct {
	Users  []User
	Groups []Group
}

// UserUpdate is a user whose own fields changed, with the before/after values.
type UserUpdate struct{ Old, New User }

// GroupUpdate is a group whose own fields changed, with before/after values.
type GroupUpdate struct{ Old, New Group }

// GroupMembership identifies a user's membership in a group.
type GroupMembership struct {
	Group  Group
	UserID string
}

// Changes is the diff between two snapshots, grouped by kind. It is returned by
// Init and delivered to Options.OnChanges by Run.
//
// When applying a batch, a safe order is: create users, then groups, then add
// memberships; remove memberships, then groups, then users. That way a member
// is never added before its group exists, nor a group removed while it still
// has members. Updates can be applied at any point.
type Changes struct {
	UsersAdded   []User
	UsersUpdated []UserUpdate
	UsersRemoved []User

	GroupsAdded   []Group
	GroupsUpdated []GroupUpdate
	GroupsRemoved []Group

	// MembersAdded/Removed cover users joining/leaving a group. Members of a
	// newly added group are reported as MembersAdded, and members of a removed
	// group as MembersRemoved, so a consumer that only wires the member
	// callbacks still sees every membership change (the group itself is also
	// reported via GroupsAdded/GroupsRemoved).
	MembersAdded   []GroupMembership
	MembersRemoved []GroupMembership
}

// IsEmpty reports whether there are no changes.
func (c Changes) IsEmpty() bool {
	return len(c.UsersAdded) == 0 && len(c.UsersUpdated) == 0 && len(c.UsersRemoved) == 0 &&
		len(c.GroupsAdded) == 0 && len(c.GroupsUpdated) == 0 && len(c.GroupsRemoved) == 0 &&
		len(c.MembersAdded) == 0 && len(c.MembersRemoved) == 0
}
