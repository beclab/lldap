package client

import "sort"

// computeChanges diffs prev -> next. Membership changes are emitted for every
// group: members of a newly added group surface as MembersAdded and members of
// a removed group as MembersRemoved, in addition to the group appearing in
// GroupsAdded/GroupsRemoved.
func computeChanges(prev, next Snapshot) Changes {
	var c Changes

	prevUsers := indexUsers(prev.Users)
	nextUsers := indexUsers(next.Users)
	for id, nu := range nextUsers {
		if pu, ok := prevUsers[id]; !ok {
			c.UsersAdded = append(c.UsersAdded, nu)
		} else if userChanged(pu, nu) {
			c.UsersUpdated = append(c.UsersUpdated, UserUpdate{Old: pu, New: nu})
		}
	}
	for id, pu := range prevUsers {
		if _, ok := nextUsers[id]; !ok {
			c.UsersRemoved = append(c.UsersRemoved, pu)
		}
	}

	prevGroups := indexGroups(prev.Groups)
	nextGroups := indexGroups(next.Groups)
	for id, ng := range nextGroups {
		pg, ok := prevGroups[id]
		if !ok {
			c.GroupsAdded = append(c.GroupsAdded, ng)
			// A brand-new group's members are all new memberships.
			for _, uid := range ng.Members {
				c.MembersAdded = append(c.MembersAdded, GroupMembership{Group: ng, UserID: uid})
			}
			continue
		}
		if groupChanged(pg, ng) {
			c.GroupsUpdated = append(c.GroupsUpdated, GroupUpdate{Old: pg, New: ng})
		}
		added, removed := diffMembers(pg.Members, ng.Members)
		for _, uid := range added {
			c.MembersAdded = append(c.MembersAdded, GroupMembership{Group: ng, UserID: uid})
		}
		for _, uid := range removed {
			c.MembersRemoved = append(c.MembersRemoved, GroupMembership{Group: ng, UserID: uid})
		}
	}
	for id, pg := range prevGroups {
		if _, ok := nextGroups[id]; !ok {
			c.GroupsRemoved = append(c.GroupsRemoved, pg)
			// A removed group's members are all lost memberships.
			for _, uid := range pg.Members {
				c.MembersRemoved = append(c.MembersRemoved, GroupMembership{Group: pg, UserID: uid})
			}
		}
	}

	c.sort()
	return c
}

// sort makes the output deterministic (maps iterate in random order).
func (c *Changes) sort() {
	sort.Slice(c.UsersAdded, func(i, j int) bool { return c.UsersAdded[i].ID < c.UsersAdded[j].ID })
	sort.Slice(c.UsersUpdated, func(i, j int) bool { return c.UsersUpdated[i].New.ID < c.UsersUpdated[j].New.ID })
	sort.Slice(c.UsersRemoved, func(i, j int) bool { return c.UsersRemoved[i].ID < c.UsersRemoved[j].ID })
	sort.Slice(c.GroupsAdded, func(i, j int) bool { return c.GroupsAdded[i].ID < c.GroupsAdded[j].ID })
	sort.Slice(c.GroupsUpdated, func(i, j int) bool { return c.GroupsUpdated[i].New.ID < c.GroupsUpdated[j].New.ID })
	sort.Slice(c.GroupsRemoved, func(i, j int) bool { return c.GroupsRemoved[i].ID < c.GroupsRemoved[j].ID })
	sort.Slice(c.MembersAdded, membershipLess(c.MembersAdded))
	sort.Slice(c.MembersRemoved, membershipLess(c.MembersRemoved))
}

func membershipLess(m []GroupMembership) func(i, j int) bool {
	return func(i, j int) bool {
		if m[i].Group.ID != m[j].Group.ID {
			return m[i].Group.ID < m[j].Group.ID
		}
		return m[i].UserID < m[j].UserID
	}
}

func indexUsers(users []User) map[string]User {
	m := make(map[string]User, len(users))
	for _, u := range users {
		m[u.ID] = u
	}
	return m
}

func indexGroups(groups []Group) map[int]Group {
	m := make(map[int]Group, len(groups))
	for _, g := range groups {
		m[g.ID] = g
	}
	return m
}

// userChanged reports whether a user's own fields changed. Group membership is
// intentionally excluded (it surfaces via the member callbacks); immutable
// CreationDate/UUID are ignored.
func userChanged(a, b User) bool {
	if a.Email != b.Email || a.DisplayName != b.DisplayName ||
		a.FirstName != b.FirstName || a.LastName != b.LastName {
		return true
	}
	return !attrsEqual(a.Attributes, b.Attributes)
}

func groupChanged(a, b Group) bool {
	return a.DisplayName != b.DisplayName || !attrsEqual(a.Attributes, b.Attributes)
}

func attrsEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || !stringSliceEqualUnordered(av, bv) {
			return false
		}
	}
	return true
}

func stringSliceEqualUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

// diffMembers returns members added to and removed from a group (by user id).
func diffMembers(prev, next []string) (added, removed []string) {
	prevSet := make(map[string]struct{}, len(prev))
	for _, u := range prev {
		prevSet[u] = struct{}{}
	}
	nextSet := make(map[string]struct{}, len(next))
	for _, u := range next {
		nextSet[u] = struct{}{}
	}
	for u := range nextSet {
		if _, ok := prevSet[u]; !ok {
			added = append(added, u)
		}
	}
	for u := range prevSet {
		if _, ok := nextSet[u]; !ok {
			removed = append(removed, u)
		}
	}
	return added, removed
}
