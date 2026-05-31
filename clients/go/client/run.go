package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Options configures Run.
type Options struct {
	// NATSURL e.g. "nats://nats.os-platform:4222".
	NATSURL  string
	NATSUser string
	NATSPass string
	// Durable names the JetStream consumer. Required, and must be a stable name
	// unique per app: two apps sharing a durable name on the same stream would
	// split each other's triggers.
	Durable string
	// StreamName is the JetStream stream to consume. Defaults to
	// DefaultStreamName ("os-stream").
	StreamName string
	// Subjects are the subjects to filter on. Defaults to DefaultSubjects
	// (os.users, os.groups). Events are only triggers, so the payload is
	// irrelevant; any message on these subjects causes a reconcile.
	Subjects []string
	// ResyncInterval is the safety-net full reconcile period. Defaults to 5m.
	ResyncInterval time.Duration
	// OnChanges receives the diff for each reconcile and must be set. See
	// ChangesHandler for the nil/error and idempotency contract.
	OnChanges ChangesHandler
	// Logger is optional.
	Logger *log.Logger
}

// Run blocks until ctx is cancelled. It connects to NATS JetStream, binds a
// durable consumer to the configured stream (default os-stream) filtering the
// configured subjects (default os.users, os.groups), then on every event
// (coalesced) and on a periodic timer fetches a full snapshot, diffs it against
// the previous one, and dispatches the changes to opts.OnChanges.
//
// Events are only triggers: the payload is never decoded, so the snapshot is
// the single source of truth and any schema is tolerated.
//
// The first reconcile diffs against the baseline recorded by Init, so changes
// during startup are delivered to OnChanges. Without a prior Init the baseline
// is empty and the entire current state is reported as additions.
//
// Run drives a single consumer loop and advances the Client's baseline as it
// goes, so call it once per Client; do not run it concurrently on the same
// Client instance.
func (c *Client) Run(ctx context.Context, opts Options) error {
	if opts.OnChanges == nil {
		return fmt.Errorf("client: Options.OnChanges must be set")
	}
	if opts.Durable == "" {
		return fmt.Errorf("client: Options.Durable must be set (a stable name unique per app)")
	}
	if opts.ResyncInterval <= 0 {
		opts.ResyncInterval = 5 * time.Minute
	}
	if opts.StreamName == "" {
		opts.StreamName = DefaultStreamName
	}
	if len(opts.Subjects) == 0 {
		opts.Subjects = DefaultSubjects
	}
	logger := opts.Logger
	if logger == nil {
		logger = log.Default()
	}

	// Keep retrying both the initial connect and any later drop: the periodic
	// resync is the safety net, but events should resume on their own once NATS
	// is reachable again instead of requiring a restart.
	natsOpts := []nats.Option{
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			logger.Printf("client: nats disconnected: %v", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Printf("client: nats reconnected to %s", nc.ConnectedUrl())
		}),
	}
	if opts.NATSUser != "" {
		natsOpts = append(natsOpts, nats.UserInfo(opts.NATSUser, opts.NATSPass))
	}
	nc, err := nats.Connect(opts.NATSURL, natsOpts...)
	if err != nil {
		return fmt.Errorf("client: connect nats: %w", err)
	}
	defer nc.Drain()

	js, err := jetstream.New(nc)
	if err != nil {
		return fmt.Errorf("client: jetstream: %w", err)
	}

	// With RetryOnFailedConnect the connection may still be establishing, so the
	// JetStream setup can fail until NATS is reachable. Retry it (respecting ctx)
	// instead of giving up, so a NATS that is not yet up at startup is tolerated.
	cons, err := setupConsumer(ctx, js, opts, logger)
	if err != nil {
		return err
	}

	// trigger is a coalescing signal: bursts collapse into a single reconcile.
	trigger := make(chan struct{}, 1)
	signal := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}

	cc, err := cons.Consume(
		func(msg jetstream.Msg) {
			_ = msg.Ack()
			logger.Printf("client: event %s", msg.Subject())
			signal()
		},
		jetstream.ConsumeErrHandler(func(_ jetstream.ConsumeContext, err error) {
			logger.Printf("client: consume error: %v", err)
		}),
	)
	if err != nil {
		return fmt.Errorf("client: consume: %w", err)
	}
	defer cc.Stop()

	// prev starts at the baseline recorded by Init; the first reconcile thus
	// reports what changed since the consumer's startup snapshot.
	c.mu.Lock()
	prev := c.baseline
	initialized := c.initialized
	c.mu.Unlock()
	if !initialized {
		logger.Printf("client: Run started without Init; the first reconcile reports the entire current state as additions")
	}
	step := func() { prev = c.reconcile(ctx, prev, opts.OnChanges, logger) }

	// Initial reconcile so consumers catch up from the baseline.
	step()

	ticker := time.NewTicker(opts.ResyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			step()
		case <-trigger:
			step()
		}
	}
}

// reconcile fetches a fresh snapshot, diffs it against prev, and applies the
// changes via onChanges. It returns the snapshot to use as the next baseline:
// next on success (or an empty diff), and prev unchanged when the snapshot
// fetch or onChanges fails, so the diff is retried on the following reconcile.
func (c *Client) reconcile(ctx context.Context, prev Snapshot, onChanges ChangesHandler, logger *log.Logger) Snapshot {
	next, err := c.Snapshot(ctx)
	if err != nil {
		logger.Printf("client: snapshot error: %v", err)
		return prev
	}
	changes := computeChanges(prev, next)
	if changes.IsEmpty() {
		return next
	}
	// Only advance the baseline when the whole batch was applied; otherwise keep
	// prev so the next reconcile re-delivers the same diff (onChanges is
	// idempotent), instead of silently dropping a failed change.
	if err := onChanges(ctx, changes); err != nil {
		logger.Printf("client: OnChanges error: %v", err)
		return prev
	}
	return next
}

// setupConsumer binds a durable consumer to the configured stream, retrying
// until it succeeds or ctx is cancelled (NATS may still be coming up at
// startup). The stream is looked up by name and only created when missing, so a
// production stream owned by another component (e.g. tapr's os-stream) is left
// untouched while a fresh local environment can still bootstrap its own.
func setupConsumer(ctx context.Context, js jetstream.JetStream, opts Options, logger *log.Logger) (jetstream.Consumer, error) {
	for {
		stream, err := js.Stream(ctx, opts.StreamName)
		if errors.Is(err, jetstream.ErrStreamNotFound) {
			stream, err = js.CreateStream(ctx, jetstream.StreamConfig{
				Name:      opts.StreamName,
				Subjects:  DefaultStreamSubjects,
				Retention: jetstream.LimitsPolicy,
				MaxAge:    24 * time.Hour,
			})
		}
		if err == nil {
			var cons jetstream.Consumer
			cons, err = stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
				Durable:        opts.Durable,
				AckPolicy:      jetstream.AckExplicitPolicy,
				DeliverPolicy:  jetstream.DeliverNewPolicy,
				FilterSubjects: opts.Subjects,
			})
			if err == nil {
				return cons, nil
			}
		}

		logger.Printf("client: nats setup pending (%v), retrying", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
