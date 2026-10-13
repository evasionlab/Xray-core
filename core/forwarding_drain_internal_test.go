package core

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/internal/forwardingdrain"
)

// Test-only access to the actual constructed instance's context. This is not
// exported in a library build and cannot authorize a caller-provided graph.
func ForwardingDrainTestContext(s *Instance) context.Context { return s.ctx }

// Holding the real lifecycle lock blocks native Start before any Start effect.
// The owned startup token must make deadline/join observable without taking
// that lock on the Seal/Join path.
type startupContext struct {
	context.Context
	values   atomic.Int32
	admitted chan struct{}
}

func (c *startupContext) Value(key any) any {
	v := c.Context.Value(key)
	// Root's second owner lookup is inside the owner admission mutex. Join
	// cannot capture until the real startup token has been registered.
	if c.values.Add(1) == 2 {
		close(c.admitted)
	}
	return v
}

func TestForwardingDrainHeldStartupDeadline(t *testing.T) {
	o, e := forwardingdrain.New([]string{"first"}, forwardingdrain.Limits{MaxParents: 8, MaxTasks: 64})
	if e != nil {
		t.Fatal(e)
	}
	observed := &startupContext{Context: forwardingdrain.WithOwner(context.Background(), o), admitted: make(chan struct{})}
	s := &Instance{ctx: observed, forwardingDrain: o, forwardingConfig: &Config{Inbound: []*InboundHandlerConfig{{Tag: "first"}}}}
	d := &ForwardingDrain{s, o}
	s.statusLock.Lock()
	var unlocked sync.Once
	defer unlocked.Do(s.statusLock.Unlock)
	done := make(chan error, 1)
	go func() { done <- s.Start() }()
	select {
	case <-observed.admitted:
	case <-time.After(3 * time.Second):
		t.Fatal("startup never acquired owner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	r, e := d.CloseAndJoin(ctx)
	if !errors.Is(e, context.DeadlineExceeded) || r != (PhysicalJoinResult{}) {
		t.Fatalf("held Start bypassed deadline %+v %v", r, e)
	}
	if e := o.CheckOpen(); !errors.Is(e, forwardingdrain.ErrClosed) {
		t.Fatal("startup wait reopened owner")
	}
	unlocked.Do(s.statusLock.Unlock)
	select {
	case e := <-done:
		if !errors.Is(e, forwardingdrain.ErrClosed) {
			t.Fatal("Start effects after seal")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("admitted Start did not join")
	}
	if r, e := d.CloseAndJoin(context.Background()); e != nil || r.CapturedTasks != 1 || r.JoinedTasks != 1 {
		t.Fatalf("startup join %+v %v", r, e)
	}
}
