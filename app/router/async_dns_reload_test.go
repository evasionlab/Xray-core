package router

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"google.golang.org/protobuf/proto"
)

func asyncReloadConfig(endpoint string) *Config {
	return &Config{DomainStrategy: Config_AsIs, Rule: []*RoutingRule{
		{RuleTag: "async", TargetTag: &RoutingRule_Tag{Tag: "ru"}, Networks: []net.Network{net.Network_TCP}, AsyncDnsRoute: &AsyncDnsRouteConfig{Endpoint: endpoint, CacheCapacity: 8, QueueCapacity: 2, Workers: 1, StaleGraceMillis: 1000}},
		{RuleTag: "fallback", TargetTag: &RoutingRule_Tag{Tag: "tunnel"}, Networks: []net.Network{net.Network_TCP}},
	}}
}

func currentAsync(r *Router) *AsyncDNSRouteMatcher {
	return asyncDNSCondition((*r.rules.Load())[0].Condition)
}

func pickedTag(t *testing.T, r *Router, domain string) string {
	t.Helper()
	route, err := r.PickRoute(swrContext(domain))
	if err != nil {
		t.Fatal(err)
	}
	return route.GetOutboundTag()
}

func TestAsyncDNSIdenticalReloadPreservesStaleWithoutRenewal(t *testing.T) {
	var unavailable atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if unavailable.Load() {
			http.Error(w, "unavailable", 503)
			return
		}
		io.WriteString(w, `{"state":"ready","route":"ru","ttlMillis":5000,"staleTtlMillis":10000,"generation":"fill-1"}`)
	}))
	defer server.Close()
	r := new(Router)
	config := asyncReloadConfig(server.URL)
	if err := r.Init(context.Background(), config, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if pickedTag(t, r, "reload.example") != "tunnel" {
		t.Fatal("initial miss did not fall back")
	}
	eventuallyAsyncDNS(t, func() bool { return currentAsync(r).Stats().Entries == 1 })
	if pickedTag(t, r, "reload.example") != "ru" {
		t.Fatal("initial RU missing")
	}
	unavailable.Store(true)
	old := currentAsync(r)
	old.mu.Lock()
	entry := old.cache["reload.example"]
	entry.freshUntil = time.Now().Add(-time.Second)
	entry.hardUntil = time.Now().Add(350 * time.Millisecond)
	entry.serverHardUntil = entry.hardUntil.Add(time.Second)
	entry.refreshAt = entry.hardUntil
	old.cache["reload.example"] = entry
	old.mu.Unlock()
	for range 4 {
		previous := currentAsync(r)
		if err := r.ReloadRules(proto.Clone(config).(*Config), false); err != nil {
			t.Fatal(err)
		}
		next := currentAsync(r)
		if next == previous || !previous.closed.Load() {
			t.Fatal("HTTP/worker lifecycle shared across reload")
		}
		next.mu.Lock()
		inherited := next.cache["reload.example"]
		next.mu.Unlock()
		if inherited != entry {
			t.Fatal("identical reload altered absolute deadlines/generation")
		}
		if pickedTag(t, r, "reload.example") != "ru" {
			t.Fatal("identical reload lost warm stale route")
		}
		// Apply updates lastUsed; preserve the observed value for next copy check.
		next.mu.Lock()
		entry = next.cache["reload.example"]
		next.mu.Unlock()
		if next.Stats().InheritedEntries != 1 {
			t.Fatal("state inheritance not observable")
		}
	}
	time.Sleep(time.Until(entry.hardUntil) + 10*time.Millisecond)
	if pickedTag(t, r, "reload.example") != "tunnel" {
		t.Fatal("reload renewed expired grace")
	}
}

func TestAsyncDNSIdenticalReloadResumesPendingWithinOriginalBudget(t *testing.T) {
	var calls atomic.Int32
	firstStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		io.Copy(io.Discard, req.Body)
		if calls.Add(1) == 1 {
			close(firstStarted)
			<-req.Context().Done()
			return
		}
		io.WriteString(w, `{"state":"ready","route":"ru","ttlMillis":5000,"staleTtlMillis":10000,"generation":"fill-1"}`)
	}))
	defer server.Close()
	config := asyncReloadConfig(server.URL)
	config.Rule[0].AsyncDnsRoute.RequestTimeoutMillis = 10000
	r := new(Router)
	if err := r.Init(context.Background(), config, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	pickedTag(t, r, "pending-reload.example")
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first HTTP request missing")
	}
	old := currentAsync(r)
	old.mu.Lock()
	original := *old.jobs["pending-reload.example"]
	old.mu.Unlock()
	if err := r.ReloadRules(config, false); err != nil {
		t.Fatal(err)
	}
	next := currentAsync(r)
	next.mu.Lock()
	copied := *next.jobs["pending-reload.example"]
	next.mu.Unlock()
	if copied.deadline != original.deadline || copied.attempts < original.attempts {
		t.Fatal("reload reset pending retry budget")
	}
	// No more route selections: copied pending work must complete autonomously.
	eventuallyAsyncDNS(t, func() bool { return next.Stats().Entries == 1 })
	if pickedTag(t, r, "pending-reload.example") != "ru" || calls.Load() != 2 {
		t.Fatal("pending work did not resume through new bounded workers")
	}
}

func TestAsyncDNSChangedRulesOrCredentialsInvalidateProjection(t *testing.T) {
	for _, change := range []string{"outbound", "grace", "credential"} {
		t.Run(change, func(t *testing.T) {
			t.Setenv("XRAY_ASYNC_DNS_BEARER_TOKEN_FILE", "")
			config := asyncReloadConfig("https://example.invalid")
			if change == "credential" {
				setAsyncDNSTestToken(t, "original-token")
			}
			r := new(Router)
			if err := r.Init(context.Background(), config, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			old := currentAsync(r)
			now := time.Now()
			old.mu.Lock()
			old.acceptResponse("changed.example", &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 60000, StaleTTLMillis: 90000, Generation: "fill-1"}, now, now)
			old.mu.Unlock()
			switch change {
			case "outbound":
				config.Rule[0].TargetTag = &RoutingRule_Tag{Tag: "different-ru"}
			case "grace":
				config.Rule[0].AsyncDnsRoute.StaleGraceMillis = 500
			case "credential":
				setAsyncDNSTestToken(t, "rotated-token")
			}
			if err := r.ReloadRules(config, false); err != nil {
				t.Fatal(err)
			}
			if currentAsync(r).Stats().Entries != 0 || currentAsync(r).Stats().InheritedEntries != 0 {
				t.Fatal("changed routing semantics/auth retained projection")
			}
			if !old.closed.Load() {
				t.Fatal("old matcher not closed")
			}
		})
	}
}

func TestAsyncDNSFailedReloadPreservesServingMatcher(t *testing.T) {
	r := new(Router)
	config := asyncReloadConfig("https://example.invalid")
	if err := r.Init(context.Background(), config, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	old := currentAsync(r)
	bad := proto.Clone(config).(*Config)
	bad.Rule[1].RuleTag = bad.Rule[0].RuleTag
	if err := r.ReloadRules(bad, false); err == nil {
		t.Fatal("duplicate tag accepted")
	}
	if currentAsync(r) != old || old.closed.Load() {
		t.Fatal("failed replacement damaged serving matcher")
	}
	if !proto.Equal(r.lastConfig, config) {
		t.Fatal("failed replacement poisoned last successful config")
	}
}

func TestAsyncDNSReloadRetainsTombstonesAndCooldownBudgets(t *testing.T) {
	r := new(Router)
	config := asyncReloadConfig("https://example.invalid")
	if err := r.Init(context.Background(), config, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	old := currentAsync(r)
	now := time.Now()
	tombstone := asyncDNSCacheEntry{routeRU: true, generation: "expired-local-fill", freshUntil: now.Add(-2 * time.Second), hardUntil: now.Add(-time.Second), serverHardUntil: now.Add(time.Minute), lastUsed: now, refreshAt: now}
	cooldown := asyncDNSJob{attempts: asyncDNSMaxAttempts, exhausted: true, deadline: now.Add(-time.Second), next: now.Add(20 * time.Second)}
	retrying := asyncDNSJob{attempts: 4, deadline: now.Add(15 * time.Second), next: now.Add(10 * time.Second)}
	old.mu.Lock()
	old.cache["tombstone.example"] = tombstone
	old.cache["dead.example"] = asyncDNSCacheEntry{serverHardUntil: now.Add(-time.Second)}
	old.jobs["cooldown.example"] = &cooldown
	old.jobs["retry.example"] = &retrying
	old.jobs["expired-job.example"] = &asyncDNSJob{deadline: now.Add(-time.Second), next: now.Add(time.Hour)}
	old.mu.Unlock()
	if err := r.ReloadRules(config, false); err != nil {
		t.Fatal(err)
	}
	next := currentAsync(r)
	next.mu.Lock()
	defer next.mu.Unlock()
	if len(next.cache) != 1 || next.cache["tombstone.example"] != tombstone {
		t.Fatal("reload lost or renewed bounded expired tombstone")
	}
	if len(next.jobs) != 2 || *next.jobs["cooldown.example"] != cooldown || *next.jobs["retry.example"] != retrying {
		t.Fatal("reload reset attempts/deadline/cooldown or resurrected expired job")
	}
}
