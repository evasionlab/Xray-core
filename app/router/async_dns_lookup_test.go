package router

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	routing_dns "github.com/xtls/xray-core/features/routing/dns"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

func lookupMatcher(t *testing.T, handler http.HandlerFunc) *AsyncDNSRouteMatcher {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: server.URL, CacheLookupWaitMillis: 150, StaleGraceMillis: 604800000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func TestAsyncDNSLookupFirstAttemptResult(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		match, hit bool
		pending    uint64
	}{
		{"ru", `{"state":"ready","route":"ru","ttlMillis":10000}`, true, true, 0},
		{"other", `{"state":"ready","route":"other","ttlMillis":10000}`, false, true, 0},
		{"stale", `{"state":"stale","route":"ru","ttlMillis":0,"staleTtlMillis":600000,"generation":"g1"}`, true, true, 0},
		{"pending", `{"state":"pending","retryAfterMillis":5000}`, false, false, 1},
		{"error", `bad json`, false, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := lookupMatcher(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, tc.body) })
			started := time.Now()
			if got := m.Apply(swrContext("cold.example")); got != tc.match {
				t.Fatalf("match=%v want %v", got, tc.match)
			}
			if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
				t.Fatalf("first attempt should release without DNS retries: %v", elapsed)
			}
			s := m.Stats()
			if s.Requests != 1 || s.LookupWaits != 1 || (s.LookupHits == 1) != tc.hit || s.LookupPending != tc.pending || s.Waiters != 0 {
				t.Fatalf("unexpected stats: %+v", s)
			}
		})
	}
}

func TestAsyncDNSLookupHardExpiredL1AndBackoff(t *testing.T) {
	m := lookupMatcher(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"state":"ready","route":"other","ttlMillis":10000,"staleTtlMillis":20000,"generation":"new"}`)
	})
	now := time.Now()
	m.mu.Lock()
	m.cache["expired.example"] = asyncDNSCacheEntry{routeRU: true, generation: "old", freshUntil: now.Add(-time.Minute), hardUntil: now.Add(-time.Second), serverHardUntil: now.Add(time.Hour)}
	m.mu.Unlock()
	if m.Apply(swrContext("expired.example")) || m.Stats().LookupHits != 1 {
		t.Fatal("hard expired L1 should synchronously use new L2 other")
	}
	m.mu.Lock()
	m.jobs["backoff.example"] = &asyncDNSJob{next: now.Add(time.Second), deadline: now.Add(asyncDNSRetryBudget), attempts: 1}
	m.mu.Unlock()
	started := time.Now()
	if m.Apply(swrContext("backoff.example")) || time.Since(started) > 20*time.Millisecond || m.Stats().LookupWaits != 1 {
		t.Fatal("backoff must not wait for another retry attempt")
	}
}

func TestAsyncDNSLookupFreshAndStaleRemainImmediate(t *testing.T) {
	m := lookupMatcher(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	now := time.Now()
	m.mu.Lock()
	m.cache["fresh.example"] = asyncDNSCacheEntry{routeRU: true, freshUntil: now.Add(time.Hour), hardUntil: now.Add(time.Hour), serverHardUntil: now.Add(time.Hour), refreshAt: now.Add(time.Hour)}
	m.cache["stale.example"] = asyncDNSCacheEntry{routeRU: true, freshUntil: now.Add(-time.Hour), hardUntil: now.Add(time.Hour), serverHardUntil: now.Add(time.Hour), refreshAt: now.Add(-time.Hour)}
	m.mu.Unlock()
	for _, domain := range []string{"fresh.example", "stale.example"} {
		started := time.Now()
		if !m.Apply(swrContext(domain)) || time.Since(started) > 20*time.Millisecond {
			t.Fatal("L1 hit blocked or did not match")
		}
	}
	if s := m.Stats(); s.LookupWaits != 0 || s.FreshHits != 1 || s.StaleHits != 1 {
		t.Fatalf("unexpected stats: %+v", s)
	}
}

func TestAsyncDNSLookupTimeoutIsNotRequestOrRetryBudget(t *testing.T) {
	m := lookupMatcher(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	m.lookupWait = 35 * time.Millisecond
	started := time.Now()
	if m.Apply(swrContext("slow.example")) {
		t.Fatal("slow lookup matched")
	}
	if elapsed := time.Since(started); elapsed < 25*time.Millisecond || elapsed > 120*time.Millisecond {
		t.Fatalf("wait did not honor total 35ms budget: %v", elapsed)
	}
	if s := m.Stats(); s.LookupTimeouts != 1 || s.Waiters != 0 || s.Jobs != 1 {
		t.Fatalf("timeout must leave bounded async job running: %+v", s)
	}
}

func TestAsyncDNSLookupConcurrentSingleflightAndCancellation(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	m := lookupMatcher(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-release:
			io.WriteString(w, `{"state":"ready","route":"ru","ttlMillis":10000}`)
		case <-r.Context().Done():
		}
	})
	caller, cancel := context.WithCancel(context.Background())
	caller = session.ContextWithOutbounds(caller, []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("shared.example"), 443)}})
	canceled := make(chan bool, 1)
	go func() { canceled <- m.Apply(routing_session.AsRoutingContext(caller)) }()
	var wg sync.WaitGroup
	const concurrency = 32
	results := make(chan bool, concurrency)
	for range concurrency {
		wg.Go(func() { results <- m.Apply(swrContext("shared.example")) })
	}
	eventuallyAsyncDNS(t, func() bool { return m.Stats().Waiters == concurrency+1 })
	cancel()
	if <-canceled {
		t.Fatal("canceled caller matched")
	}
	close(release)
	wg.Wait()
	for range concurrency {
		if !<-results {
			t.Fatal("shared ready result did not match")
		}
	}
	if calls.Load() != 1 || m.Stats().LookupCanceled != 1 || m.Stats().Waiters != 0 {
		t.Fatalf("dedupe/cancel failed: calls=%d stats=%+v", calls.Load(), m.Stats())
	}
}

func TestAsyncDNSLookupCloseAndAdmission(t *testing.T) {
	m := lookupMatcher(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	// Reserve the fixed number of admission slots; no unbounded caller queue.
	for range asyncDNSMaxWaiters {
		m.waiters <- struct{}{}
	}
	started := time.Now()
	if m.Apply(swrContext("overflow.example")) || time.Since(started) > 20*time.Millisecond || m.Stats().LookupRejected != 1 {
		t.Fatal("full waiter admission must fail open immediately")
	}
	for range asyncDNSMaxWaiters {
		<-m.waiters
	}
	result := make(chan bool, 1)
	go func() { result <- m.Apply(swrContext("close.example")) }()
	eventuallyAsyncDNS(t, func() bool { return m.Stats().Waiters == 1 })
	m.Close()
	select {
	case matched := <-result:
		if matched || m.Stats().Waiters != 0 {
			t.Fatal("Close did not release waiters")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Close waiter stuck")
	}
}

func TestAsyncDNSLookupReloadDoesNotShareCompletionChannels(t *testing.T) {
	m := lookupMatcher(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	result := make(chan bool, 1)
	go func() { result <- m.Apply(swrContext("reload.example")) }()
	eventuallyAsyncDNS(t, func() bool { return m.Stats().Waiters == 1 })
	next := lookupMatcher(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"state":"ready","route":"ru","ttlMillis":10000}`)
	})
	m.mu.Lock()
	deadline := m.jobs["reload.example"].deadline
	oldAttempt := m.jobs["reload.example"].attempt
	m.mu.Unlock()
	next.inheritState(m)
	next.mu.Lock()
	job := next.jobs["reload.example"]
	if job == nil || job.attempt == oldAttempt || !job.deadline.Equal(deadline) {
		t.Fatal("reload copied in-flight state or reset deadline")
	}
	next.mu.Unlock()
	m.Close()
	if <-result {
		t.Fatal("closed old matcher matched")
	}
	eventuallyAsyncDNS(t, func() bool { return next.Stats().Entries == 1 })
	if !next.Apply(swrContext("reload.example")) {
		t.Fatal("new matcher did not resume job")
	}
}

func TestAsyncDNSLookupOneBudgetAcrossRulesAndDNSPass(t *testing.T) {
	first := lookupMatcher(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(45 * time.Millisecond)
		io.WriteString(w, `{"state":"pending"}`)
	})
	second := lookupMatcher(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	first.lookupWait = 100 * time.Millisecond
	second.lookupWait = 100 * time.Millisecond
	ctx := withAsyncDNSWaitBudget(swrContext("budget.example"))
	started := time.Now()
	if first.Apply(ctx) || second.Apply(ctx) {
		t.Fatal("pending/slow attempts matched")
	}
	// The DNS wrapper must retain the already spent route budget.
	ctx = routing_dns.ContextWithDNSClient(ctx, nil)
	if second.Apply(ctx) {
		t.Fatal("second pass matched")
	}
	if elapsed := time.Since(started); elapsed > 130*time.Millisecond || elapsed < 90*time.Millisecond {
		t.Fatalf("rules/passes reset total wait budget: %v", elapsed)
	}
}

func TestAsyncDNSLookupRouterBudgetAndCallerCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer server.Close()
	r := new(Router)
	config := asyncReloadConfig(server.URL)
	config.Rule[0].AsyncDnsRoute.CacheLookupWaitMillis = 100
	second := &RoutingRule{RuleTag: "async2", TargetTag: &RoutingRule_Tag{Tag: "ru2"}, AsyncDnsRoute: &AsyncDnsRouteConfig{Endpoint: server.URL, CacheLookupWaitMillis: 100}}
	config.Rule = append(config.Rule[:1], second, config.Rule[1])
	if err := r.Init(context.Background(), config, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	started := time.Now()
	if tag := pickedTag(t, r, "router-budget.example"); tag != "tunnel" || time.Since(started) > 170*time.Millisecond {
		t.Fatal("Router reset budget across async rules")
	}
	caller, cancel := context.WithCancel(context.Background())
	caller = session.ContextWithOutbounds(caller, []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress("cancel-router.example"), 443)}})
	result := make(chan struct{})
	go func() {
		defer close(result)
		r.PickRoute(routing_session.AsRoutingContext(caller))
	}()
	eventuallyAsyncDNS(t, func() bool { return currentAsync(r).Stats().Waiters == 1 })
	cancel()
	select {
	case <-result:
	case <-time.After(70 * time.Millisecond):
		t.Fatal("Router did not propagate caller cancellation")
	}
}

func TestAsyncDNSLookupConfigBoundsAndSevenDayGrace(t *testing.T) {
	if _, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: "http://example.com", CacheLookupWaitMillis: 251}); err == nil {
		t.Fatal("unbounded wait accepted")
	}
	m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: "http://example.com", CacheLookupWaitMillis: 250, StaleGraceMillis: 604800000})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	now := time.Now()
	m.mu.Lock()
	m.acceptResponse("long.example", &asyncDNSClassifierResponse{State: "stale", Route: "ru", StaleTTLMillis: 604800000, Generation: "fill"}, now, now)
	entry := m.cache["long.example"]
	m.mu.Unlock()
	if entry.hardUntil.Sub(now) != 7*24*time.Hour || entry.freshUntil.After(now) {
		t.Fatal("long stale grace changed DNS freshness or retention")
	}
}
