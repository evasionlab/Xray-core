package forwardingdrain

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// The wrapper holds a real native Close call, not a synthetic forwarding task.
type heldConnection struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
}

func (c *heldConnection) Close() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Conn.Close()
}

func testOwner(t *testing.T) (*Owner, context.Context) {
	t.Helper()
	o, e := New([]string{"a", "b"}, Limits{8, 64})
	if e != nil {
		t.Fatal(e)
	}
	return o, ListenerContext(WithOwner(context.Background(), o), "a")
}

func await(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(3 * time.Second):
		t.Fatal("owned operation did not complete")
	}
}

func TestJoinDeadlineOwnsHeldNativeInterruption(t *testing.T) {
	o, ctx := testOwner(t)
	a, b := net.Pipe()
	defer b.Close()
	held := &heldConnection{Conn: a, entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(held.release) })
	root, e := Root(ctx, true, held)
	if e != nil {
		t.Fatal(e)
	}
	// Completion of a forwarding token alone is insufficient: interruption must
	// finish too. This also exercises a concurrent Seal joining the same batch.
	rootDone := make(chan struct{})
	go func() { <-root.ctx.Done(); root.Done(); close(rootDone) }()
	o.Seal()
	await(t, held.entered)
	o.Seal()
	await(t, rootDone)
	timeout, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	r, e := o.Join(timeout)
	if !errors.Is(e, context.DeadlineExceeded) || r != (Result{}) {
		t.Fatalf("held Close fabricated completion: %+v %v", r, e)
	}
	if _, e := Root(ctx, true); !errors.Is(e, ErrClosed) {
		t.Fatal("sealed owner reopened")
	}
	release.Do(func() { close(held.release) })
	join, cancelJoin := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelJoin()
	r, e = o.Join(join)
	if e != nil || r.CapturedParents != 1 || r.JoinedParents != 1 || r.FinalAccounting != "not_proven" {
		t.Fatalf("real completion: %+v %v", r, e)
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if r, e = o.Join(canceled); !errors.Is(e, context.Canceled) || r != (Result{}) {
		t.Fatal("cancelled read claimed completion")
	}
}

type observedInterrupt struct {
	done chan struct{}
	once sync.Once
}

func (x *observedInterrupt) Interrupt() { x.once.Do(func() { close(x.done) }) }
func TestRunJoinedWaitsActualSiblingCleanup(t *testing.T) {
	o, ctx := testOwner(t)
	root, e := Root(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	entered, release, cleaned, finished := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	failed := errors.New("copy failed")
	stopped := &observedInterrupt{done: make(chan struct{})}
	go func() {
		e := RunJoined(root.ctx, []any{stopped}, func() error { <-entered; return failed }, func() error { close(entered); <-release; close(cleaned); return nil })
		if !errors.Is(e, failed) {
			t.Error("lost original copy error")
		}
		root.Done()
		close(finished)
	}()
	await(t, entered)
	await(t, stopped.done)
	timeout, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if r, e := o.Join(timeout); !errors.Is(e, context.DeadlineExceeded) || r != (Result{}) {
		t.Fatalf("unjoined sibling: %+v %v", r, e)
	}
	once.Do(func() { close(release) })
	await(t, cleaned)
	await(t, finished)
	join, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if r, e := o.Join(join); e != nil || r.JoinedTasks != 1 || r.JoinedParents != 1 {
		t.Fatalf("wrong owned sibling result %+v %v", r, e)
	}
}

func TestTokenParentWaitsChildrenAndRejectsLateAdmission(t *testing.T) {
	o, ctx := testOwner(t)
	root, e := Root(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	child, e := Child(root.ctx)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() { root.Done(); close(done) }()
	await(t, root.ctx.Done())
	if _, e := Child(root.ctx); !errors.Is(e, ErrAuthority) {
		t.Fatal("finishing parent admitted child")
	}
	select {
	case <-done:
		t.Fatal("parent completion preceded child")
	default:
	}
	child.Done()
	await(t, done)
	if r, e := o.Join(context.Background()); e != nil || r.CapturedParents != 0 {
		t.Fatalf("already completed census %+v %v", r, e)
	}
}

func TestCapacityAndFixedRootCensus(t *testing.T) {
	o, e := New([]string{"a"}, Limits{1, 8})
	if e != nil {
		t.Fatal(e)
	}
	ctx := ListenerContext(WithOwner(context.Background(), o), "foreign")
	if _, e := Root(ctx, true); !errors.Is(e, ErrAuthority) {
		t.Fatal("foreign root allowed")
	}
	ctx = ListenerContext(ctx, "a")
	r, e := Root(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Root(ctx, true); !errors.Is(e, ErrCapacity) {
		t.Fatal("parent capacity not bounded")
	}
	r.Done()
	o.Seal()
}
