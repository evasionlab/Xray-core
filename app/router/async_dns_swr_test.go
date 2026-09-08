package router

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

func swrContext(domain string) *routing_session.Context {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: net.TCPDestination(net.DomainAddress(domain), 443)}})
	return routing_session.AsRoutingContext(ctx).(*routing_session.Context)
}

func eventuallyAsyncDNS(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("async DNS condition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAsyncDNSAutonomousPendingCompletion(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			io.WriteString(w, `{"state":"pending","retryAfterMillis":10}`)
			return
		}
		io.WriteString(w, `{"state":"ready","route":"ru","ttlMillis":5000}`)
	}))
	defer server.Close()
	m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if m.Apply(swrContext("pending.example")) {
		t.Fatal("cold miss matched")
	}
	// No Apply calls during pending: the scheduler must finish the fill itself.
	eventuallyAsyncDNS(t, func() bool { return m.Stats().Entries == 1 })
	if calls.Load() != 2 || !m.Apply(swrContext("pending.example")) {
		t.Fatal("pending did not autonomously become RU")
	}
}

func projectionMatcher(grace time.Duration) *AsyncDNSRouteMatcher {
	return &AsyncDNSRouteMatcher{cache: make(map[string]asyncDNSCacheEntry), cacheCapacity: 8, maxTTL: time.Minute, staleGrace: grace}
}

func TestAsyncDNSAuthoritativeFreshAndHardDeadlines(t *testing.T) {
	now := time.Now()
	m := projectionMatcher(10 * time.Minute)
	ready := &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 1000, StaleTTLMillis: 900000}
	if !m.acceptResponse("ru.example", ready, now.Add(-100*time.Millisecond), now) {
		t.Fatal("valid ready rejected")
	}
	entry := m.cache["ru.example"]
	if entry.freshUntil.Sub(now) != 900*time.Millisecond || entry.hardUntil.Sub(now) != 10*time.Minute+900*time.Millisecond {
		t.Fatalf("incorrect elapsed/local-grace bounds: %+v", entry)
	}
	oldHard := entry.hardUntil
	later := now.Add(2 * time.Second)
	stale := &asyncDNSClassifierResponse{State: "stale", Route: "ru", StaleTTLMillis: 900000}
	if m.acceptResponse("ru.example", stale, later, later) {
		t.Fatal("stale must continue retrying")
	}
	if m.cache["ru.example"].hardUntil.After(oldHard) {
		t.Fatal("stale extended hard deadline")
	}
	if !m.acceptResponse("ru.example", &asyncDNSClassifierResponse{State: "ready", Route: "other", TTLMillis: 5000, StaleTTLMillis: 10000}, later, later) {
		t.Fatal("fresh other rejected")
	}
	if m.cache["ru.example"].routeRU {
		t.Fatal("fresh other did not supersede stale RU")
	}
}

func TestAsyncDNSLegacyAndMalformedResponsesCannotCreateGrace(t *testing.T) {
	now := time.Now()
	for _, grace := range []time.Duration{0, time.Minute} {
		m := projectionMatcher(grace)
		if !m.acceptResponse("legacy.example", &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 100}, now, now) {
			t.Fatal("legacy response rejected")
		}
		original := m.cache["legacy.example"]
		if original.hardUntil != original.freshUntil {
			t.Fatal("legacy response fabricated stale grace")
		}
		for _, response := range []*asyncDNSClassifierResponse{
			{State: "ready", Route: "other", TTLMillis: 0},
			{State: "ready", Route: "other", TTLMillis: 100, StaleTTLMillis: 50},
			{State: "ready", Route: "unknown", TTLMillis: 100},
			{State: "unknown", Route: "other", TTLMillis: 100},
			{State: "stale", Route: "other", TTLMillis: 100, StaleTTLMillis: 200},
			{State: "stale", Route: "other", StaleTTLMillis: 0},
			{State: "pending", Route: "other", TTLMillis: 100},
			{State: "ready", Route: "other", TTLMillis: 100, Generation: strings.Repeat("x", 129)},
		} {
			if m.acceptResponse("legacy.example", response, now, now) {
				t.Fatalf("invalid response accepted: %+v", response)
			}
			if m.cache["legacy.example"] != original {
				t.Fatal("invalid response erased or changed last-good")
			}
		}
		if m.acceptResponse("expired.example", &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 10}, now.Add(-20*time.Millisecond), now) {
			t.Fatal("network elapsed freshness must not be inflated by min TTL")
		}
	}
	m := projectionMatcher(0)
	m.acceptResponse("stale.example", &asyncDNSClassifierResponse{State: "stale", Route: "ru", StaleTTLMillis: 1000}, now, now)
	if len(m.cache) != 0 {
		t.Fatal("stale routing enabled by default")
	}
}

func TestAsyncDNSPrefetchOutageAndHardExpiry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request asyncDNSClassifierRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || !request.AllowStale {
			t.Error("missing stale opt-in")
		}
		if calls.Add(1) == 1 {
			io.WriteString(w, `{"state":"ready","route":"ru","ttlMillis":180,"staleTtlMillis":700}`)
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: server.URL, StaleGraceMillis: 1000})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx := swrContext("outage.example")
	m.Apply(ctx)
	eventuallyAsyncDNS(t, func() bool { return m.Stats().Entries == 1 })
	m.mu.Lock()
	entry := m.cache["outage.example"]
	m.mu.Unlock()
	// Proactive refresh happens without another client connection.
	eventuallyAsyncDNS(t, func() bool { return calls.Load() >= 2 })
	if time.Now().After(entry.hardUntil) {
		t.Fatal("test exceeded hard deadline")
	}
	time.Sleep(time.Until(entry.freshUntil) + 10*time.Millisecond)
	if !m.Apply(ctx) {
		t.Fatal("known RU fell back during bounded outage grace")
	}
	time.Sleep(time.Until(entry.hardUntil) + 10*time.Millisecond)
	if m.Apply(ctx) {
		t.Fatal("outage extended last-good beyond hard retention")
	}
	if m.Stats().StaleHits == 0 || m.Stats().Errors == 0 {
		t.Fatal("missing stale/error observability")
	}
}

func TestAsyncDNSQueueFloodAndCloseAreBounded(t *testing.T) {
	entered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: server.URL, CacheCapacity: 4, QueueCapacity: 1, Workers: 1, RequestTimeoutMillis: 10000})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 500 {
		started := time.Now()
		m.Apply(swrContext(fmt.Sprintf("host%d.example", i)))
		if time.Since(started) > 20*time.Millisecond {
			t.Fatal("cold Apply blocked during queue flood")
		}
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker never started")
	}
	stats := m.Stats()
	if stats.Jobs > 4 || stats.Entries > 4 || stats.Queued > 1 || stats.QueueDrops == 0 {
		t.Fatalf("unbounded flood state: %+v", stats)
	}
	started := time.Now()
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("Close did not cancel blocked HTTP request")
	}
	if m.Apply(swrContext("after-close.example")) {
		t.Fatal("closed matcher still matched")
	}
	m.Close()
}

func TestAsyncDNSRetryExhaustionHasCooldown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "unavailable", 503) }))
	defer server.Close()
	m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.mu.Lock()
	m.jobs["exhausted.example"] = &asyncDNSJob{deadline: time.Now().Add(time.Minute), attempts: asyncDNSMaxAttempts, queued: true}
	m.mu.Unlock()
	m.refresh("exhausted.example")
	m.mu.Lock()
	job := *m.jobs["exhausted.example"]
	m.mu.Unlock()
	if !job.exhausted || job.next.Before(time.Now().Add(29*time.Second)) {
		t.Fatal("exhausted retries did not enter bounded cooldown")
	}
	if m.Stats().Requests != 1 || m.Stats().Exhausted != 1 {
		t.Fatal("exhaustion counters missing")
	}
}

func TestAsyncDNSRejectsUnboundedGrace(t *testing.T) {
	if _, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: "http://example.com", StaleGraceMillis: 3600001}); err == nil {
		t.Fatal("unbounded grace accepted")
	}
}

func TestAsyncDNSGenerationControlsRetentionRenewal(t *testing.T) {
	now := time.Now()
	m := projectionMatcher(10 * time.Minute)
	initial := &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 300000, StaleTTLMillis: 900000, Generation: "fill-1"}
	m.acceptResponse("ru.example", initial, now, now)
	first := m.cache["ru.example"]
	if first.hardUntil.Sub(now) != 11*time.Minute {
		t.Fatal("local maxTTL + grace bound missing")
	}
	later := now.Add(30 * time.Second)
	reread := &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 270000, StaleTTLMillis: 870000, Generation: "fill-1"}
	m.acceptResponse("ru.example", reread, later, later)
	if m.cache["ru.example"].hardUntil != first.hardUntil {
		t.Fatal("same L2 generation slid local stale allowance")
	}
	reread.Generation = "fill-2"
	m.acceptResponse("ru.example", reread, later, later)
	if !m.cache["ru.example"].hardUntil.After(first.hardUntil) {
		t.Fatal("genuine fresh DNS fill did not renew retention")
	}
	newHard := m.cache["ru.example"].hardUntil
	reread.Generation = ""
	later = later.Add(30 * time.Second)
	m.acceptResponse("ru.example", reread, later, later)
	if m.cache["ru.example"].hardUntil != newHard {
		t.Fatal("missing generation minted new grace")
	}
	// Even a different generation marked stale cannot extend existing grace.
	later = now.Add(6 * time.Minute)
	m.acceptResponse("ru.example", &asyncDNSClassifierResponse{State: "stale", Route: "ru", StaleTTLMillis: 800000, Generation: "fill-3"}, later, later)
	if m.cache["ru.example"].hardUntil != newHard {
		t.Fatal("stale response extended existing retention")
	}
}

func TestAsyncDNSExpiredTombstonePreventsStaleResurrection(t *testing.T) {
	now := time.Now()
	m := projectionMatcher(time.Second)
	m.acceptResponse("ru.example", &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 100, StaleTTLMillis: 10000, Generation: "fill-1"}, now, now)
	first := m.cache["ru.example"]
	later := now.Add(2 * time.Second)
	if m.acceptResponse("ru.example", &asyncDNSClassifierResponse{State: "stale", Route: "ru", StaleTTLMillis: 8000, Generation: "fill-1"}, later, later) {
		t.Fatal("expired stale generation accepted")
	}
	if m.cache["ru.example"] != first {
		t.Fatal("expired tombstone was resurrected")
	}
}

func TestAsyncDNSFreshReadAfterLocalExpiryDoesNotMintStaleGrace(t *testing.T) {
	now := time.Now()
	m := projectionMatcher(time.Second)
	m.maxTTL = time.Second
	m.acceptResponse("ru.example", &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 10000, StaleTTLMillis: 20000, Generation: "fill-1"}, now, now)
	later := now.Add(3 * time.Second)
	if !m.acceptResponse("ru.example", &asyncDNSClassifierResponse{State: "ready", Route: "ru", TTLMillis: 7000, StaleTTLMillis: 17000, Generation: "fill-1"}, later, later) {
		t.Fatal("authoritative fresh result rejected")
	}
	entry := m.cache["ru.example"]
	if entry.freshUntil != later.Add(time.Second) || entry.hardUntil != entry.freshUntil {
		t.Fatal("fresh reread minted stale grace")
	}
}
