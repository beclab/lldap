package client

// This file defines the NATS conventions the SDK consumes. In Olares the
// account event bus uses the os.users / os.groups subjects on the os-stream
// JetStream stream (published by app-service today).
//
// Events are treated purely as a trigger: receiving any message merely tells
// Run to re-fetch a full LLDAP snapshot and reconcile, so the payload is never
// decoded and its schema does not affect correctness. The snapshot is the
// source of truth.

// Default JetStream conventions, overridable via Options.
const (
	// DefaultStreamName is the Olares system stream that carries os.* events.
	DefaultStreamName = "os-stream"
)

// Olares account event subjects consumed as reconcile triggers.
const (
	SubjectUsers  = "os.users"
	SubjectGroups = "os.groups"
)

// DefaultSubjects are the subjects the consumer filters on by default.
var DefaultSubjects = []string{SubjectUsers, SubjectGroups}

// DefaultStreamSubjects is used only when the SDK has to create the stream
// itself (e.g. local dev where no os-stream exists yet). It is a superset of
// DefaultSubjects so future os.* events are captured too.
var DefaultStreamSubjects = []string{"os.>"}
