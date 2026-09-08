package router

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/features/routing"
)

// Optional extension: external routing.Context implementations remain compatible.
func asyncDNSCallerContext(ctx routing.Context) context.Context {
	if carrier, ok := ctx.(interface{ GetContext() context.Context }); ok {
		if caller := carrier.GetContext(); caller != nil {
			return caller
		}
	}
	return context.Background()
}

type asyncDNSWaitBudgetKey struct{}

type asyncDNSWaitBudget struct {
	mu       sync.Mutex
	deadline time.Time
}

func (b *asyncDNSWaitBudget) limit(deadline time.Time) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.deadline.IsZero() || deadline.Before(b.deadline) {
		b.deadline = deadline
	}
	return b.deadline
}

type asyncDNSRoutingContext struct {
	routing.Context
	caller context.Context
}

func (ctx *asyncDNSRoutingContext) GetContext() context.Context { return ctx.caller }

// One absolute wait budget across rules and an IPIfNonMatch second pass. A new
// route selection gets its own budget; retries within it cannot reset deadlines.
func withAsyncDNSWaitBudget(ctx routing.Context) routing.Context {
	return &asyncDNSRoutingContext{Context: ctx, caller: context.WithValue(asyncDNSCallerContext(ctx), asyncDNSWaitBudgetKey{}, &asyncDNSWaitBudget{})}
}
