// Package forwardingdrain owns volatile, same-instance forwarding completion.
// It is internal: no remote actor, durable restart or financial authority.
package forwardingdrain

import (
	"context"
	"errors"
	"io"
	"sync"
)

var (
	ErrClosed      = errors.New("forwarding drain closed")
	ErrAuthority   = errors.New("forwarding drain authority mismatch")
	ErrCapacity    = errors.New("forwarding drain capacity exceeded")
	ErrUnsupported = errors.New("forwarding drain graph unsupported")
)

type (
	Limits struct{ MaxParents, MaxTasks uint32 }
	Result struct {
		CapturedParents uint32
		JoinedParents   uint32
		CapturedTasks   uint32
		JoinedTasks     uint32
		PhysicalJoin    string
		FinalAccounting string
	}
)

type Owner struct {
	mu                             sync.Mutex
	tags                           map[string]struct{}
	limits                         Limits
	entries                        map[*Token]struct{}
	parents, tasks                 uint32
	idle                           chan struct{}
	cleanupDone                    chan struct{}
	sealed                         bool
	capturedParents, capturedTasks uint32
}
type Token struct {
	owner        *Owner
	ctx          context.Context
	cancel       context.CancelFunc
	parent       bool
	done         bool
	resources    []any
	parentToken  *Token
	children     uint32
	childrenIdle chan struct{}
	finishing    bool
	once         sync.Once
}
type (
	ownerKey struct{}
	tokenKey struct{}
	tagKey   struct{}
)

func New(tags []string, limits Limits) (*Owner, error) {
	if len(tags) < 1 || len(tags) > 2 || limits.MaxParents < 1 || limits.MaxParents > 65536 || limits.MaxTasks < 8 || limits.MaxTasks > 1048576 {
		return nil, ErrCapacity
	}
	m := map[string]struct{}{}
	for _, tag := range tags {
		if tag == "" || len(tag) > 128 {
			return nil, ErrAuthority
		}
		if _, ok := m[tag]; ok {
			return nil, ErrAuthority
		}
		m[tag] = struct{}{}
	}
	idle := make(chan struct{})
	close(idle)
	return &Owner{tags: m, limits: limits, entries: map[*Token]struct{}{}, idle: idle}, nil
}

func WithOwner(ctx context.Context, o *Owner) context.Context {
	return context.WithValue(ctx, ownerKey{}, o)
}

func FromContext(ctx context.Context) *Owner {
	if ctx == nil {
		return nil
	}
	o, _ := ctx.Value(ownerKey{}).(*Owner)
	return o
}

func ListenerContext(ctx context.Context, tag string) context.Context {
	return context.WithValue(ctx, tagKey{}, tag)
}

func (o *Owner) CheckOpen() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.sealed {
		return ErrClosed
	}
	return nil
}

// CheckParent requires a live, same-owner registered native-parent lineage.
// It is a read guard before dispatcher allocations; Child rechecks atomically.
func (o *Owner) CheckParent(ctx context.Context) error {
	if o == nil || ctx == nil || FromContext(ctx) != o {
		return ErrAuthority
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.sealed {
		return ErrClosed
	}
	t, _ := ctx.Value(tokenKey{}).(*Token)
	for t != nil {
		if t.owner != o || t.done || t.finishing {
			return ErrAuthority
		}
		if _, ok := o.entries[t]; !ok {
			return ErrAuthority
		}
		if t.parent {
			return nil
		}
		t = t.parentToken
	}
	return ErrAuthority
}

func stop(resources []any) {
	for _, r := range resources {
		if x, ok := r.(interface{ Interrupt() }); ok {
			x.Interrupt()
		}
		if x, ok := r.(io.Closer); ok {
			x.Close()
		}
	}
}

func (o *Owner) acquire(ctx context.Context, parent bool, root bool, resources []any) (*Token, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if FromContext(ctx) != o {
		return nil, ErrAuthority
	}
	if o.sealed {
		return nil, ErrClosed
	}
	if root {
		tag, _ := ctx.Value(tagKey{}).(string)
		if _, ok := o.tags[tag]; !ok {
			return nil, ErrAuthority
		}
	} else {
		p, _ := ctx.Value(tokenKey{}).(*Token)
		if p == nil {
			return nil, ErrAuthority
		}
		for ancestor := p; ancestor != nil; ancestor = ancestor.parentToken {
			if ancestor.owner != o || ancestor.done || ancestor.finishing {
				return nil, ErrAuthority
			}
			if _, ok := o.entries[ancestor]; !ok {
				return nil, ErrAuthority
			}
		}
	}
	if (parent && o.parents >= o.limits.MaxParents) || (!parent && o.tasks >= o.limits.MaxTasks) {
		return nil, ErrCapacity
	}
	if len(o.entries) == 0 {
		o.idle = make(chan struct{})
	}
	child, cancel := context.WithCancel(ctx)
	t := &Token{owner: o, cancel: cancel, parent: parent, resources: append([]any(nil), resources...)}
	t.childrenIdle = make(chan struct{})
	close(t.childrenIdle)
	if !root {
		p, _ := ctx.Value(tokenKey{}).(*Token)
		t.parentToken = p
		if p.children == 0 {
			p.childrenIdle = make(chan struct{})
		}
		p.children++
	}
	t.ctx = context.WithValue(child, tokenKey{}, t)
	o.entries[t] = struct{}{}
	if parent {
		o.parents++
	} else {
		o.tasks++
	}
	return t, nil
}

func Root(ctx context.Context, parent bool, resources ...any) (*Token, error) {
	o := FromContext(ctx)
	if o == nil {
		return nil, nil
	}
	return o.acquire(ctx, parent, true, resources)
}

func Parent(ctx context.Context, resources ...any) (*Token, error) {
	o := FromContext(ctx)
	if o == nil {
		return nil, nil
	}
	return o.acquire(ctx, true, false, resources)
}

func Child(ctx context.Context, resources ...any) (*Token, error) {
	o := FromContext(ctx)
	if o == nil {
		return nil, nil
	}
	return o.acquire(ctx, false, false, resources)
}

func (t *Token) Context(fallback context.Context) context.Context {
	if t == nil {
		return fallback
	}
	return t.ctx
}

func (t *Token) Done() {
	if t == nil {
		return
	}
	t.once.Do(func() {
		o := t.owner
		o.mu.Lock()
		t.finishing = true
		idle := t.childrenIdle
		o.mu.Unlock()
		t.cancel()
		<-idle
		o.mu.Lock()
		t.done = true
		delete(o.entries, t)
		if t.parent {
			o.parents--
		} else {
			o.tasks--
		}
		if p := t.parentToken; p != nil {
			p.children--
			if p.children == 0 {
				close(p.childrenIdle)
			}
		}
		if len(o.entries) == 0 {
			close(o.idle)
		}
		o.mu.Unlock()
	})
}

// Seal closes admission synchronously. One owned interruption batch completes
// all captured native interruption calls. Join waits this batch as well as all
// forwarding tokens; a blocked Close cannot bypass the caller's Join deadline.
func (o *Owner) Seal() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.sealed {
		o.mu.Unlock()
		return
	}
	o.sealed = true
	o.capturedParents, o.capturedTasks = o.parents, o.tasks
	tokens := make([]*Token, 0, len(o.entries))
	for t := range o.entries {
		tokens = append(tokens, t)
	}
	o.cleanupDone = make(chan struct{})
	cleanup := o.cleanupDone
	o.mu.Unlock()
	// Cancellation cannot invoke native closers. Publish it for every captured
	// token before a possibly held native interruption call in the single batch.
	for _, t := range tokens {
		t.cancel()
	}
	go func() {
		defer close(cleanup)
		for _, t := range tokens {
			stop(t.resources)
		}
	}()
}

func (o *Owner) Join(ctx context.Context) (Result, error) {
	if o == nil || ctx == nil {
		return Result{}, ErrAuthority
	}
	o.Seal()
	o.mu.Lock()
	idle, cleanup := o.idle, o.cleanupDone
	o.mu.Unlock()
	for _, done := range []<-chan struct{}{cleanup, idle} {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-done:
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return Result{CapturedParents: o.capturedParents, JoinedParents: o.capturedParents, CapturedTasks: o.capturedTasks, JoinedTasks: o.capturedTasks, PhysicalJoin: "completed", FinalAccounting: "not_proven"}, nil
}

// RunJoined is only called by selected native proxy branches. Every actual copy
// is registered before go and completes after its cleanup. Cancellation/error
// stops owned endpoints, then joins siblings; it cannot synthesize completion.
func RunJoined(ctx context.Context, resources []any, tasks ...func() error) error {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	tokens := make([]*Token, 0, len(tasks))
	for range tasks {
		t, e := Child(child, resources...)
		if e != nil {
			for _, old := range tokens {
				old.Done()
			}
			stop(resources)
			return e
		}
		tokens = append(tokens, t)
	}
	done := make(chan error, len(tasks))
	for i, f := range tasks {
		go func(t *Token, f func() error) { e := f(); t.Done(); done <- e }(tokens[i], f)
	}
	var first error
	completed := 0
	cancelled := false
	for completed < len(tasks) {
		if cancelled {
			e := <-done
			if first == nil && e != nil {
				first = e
			}
			completed++
			continue
		}
		select {
		case e := <-done:
			completed++
			if e != nil && first == nil {
				first = e
				cancelled = true
				cancel()
				stop(resources)
			}
		case <-ctx.Done():
			first = ctx.Err()
			cancelled = true
			cancel()
			stop(resources)
		}
	}
	return first
}
