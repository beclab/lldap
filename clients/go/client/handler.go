package client

import "context"

// ChangesHandler applies one reconcile's worth of diff to the consumer's own
// store. It is the single callback Run invokes (and the natural shape to also
// hand the Changes that Init returns), so a consumer writes one apply function
// and reuses it for both startup and streaming.
//
// Contract:
//   - Return nil ONLY when the entire batch has been applied successfully.
//   - Returning an error makes Run keep its baseline and re-deliver the SAME
//     (and any newer) changes on the next reconcile, instead of dropping them.
//   - Therefore the handler MUST be idempotent: applying the same Changes more
//     than once must be safe (delivery is at-least-once and failed batches are
//     retried).
type ChangesHandler func(ctx context.Context, c Changes) error
