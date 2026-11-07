package router

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

func TestAsyncDNSNonRURequiresPositiveFreshProof(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		body    string
		transit time.Duration
		want    bool
	}{
		{"all-known-nonru", `{"state":"ready","route":"other","nonRuConfirmed":true,"ttlMillis":1000,"staleTtlMillis":10000}`, 0, true},
		{"legacy-other", `{"state":"ready","route":"other","ttlMillis":1000}`, 0, false},
		{"mixed-or-unknown", `{"state":"ready","route":"other","nonRuConfirmed":false,"ttlMillis":1000}`, 0, false},
		{"ru", `{"state":"ready","route":"ru","ttlMillis":1000}`, 0, false},
		{"contradictory-ru", `{"state":"ready","route":"ru","nonRuConfirmed":true,"ttlMillis":1000}`, 0, false},
		{"pending", `{"state":"pending","nonRuConfirmed":true}`, 0, false},
		{"stale-other", `{"state":"stale","route":"other","nonRuConfirmed":true,"staleTtlMillis":10000}`, 0, false},
		{"expired-in-transit", `{"state":"ready","route":"other","nonRuConfirmed":true,"ttlMillis":100,"staleTtlMillis":10000}`, time.Second, false},
		{"unknown-route", `{"state":"ready","route":"unknown","nonRuConfirmed":true,"ttlMillis":1000}`, 0, false},
		{"unknown-state", `{"state":"error","route":"other","nonRuConfirmed":true,"ttlMillis":1000}`, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := projectionMatcher(time.Minute)
			m.matchNonRU = true
			var response asyncDNSClassifierResponse
			if err := json.Unmarshal([]byte(tc.body), &response); err != nil {
				t.Fatal(err)
			}
			m.acceptResponse("test.example", &response, now.Add(-tc.transit), now)
			got, found := m.lookup("test.example", now)
			if found && got != tc.want || !found && tc.want {
				t.Fatalf("match=%v found=%v want=%v", got, found, tc.want)
			}
		})
	}
}

func TestAsyncDNSNonRUProofExpiresWithoutStaleAuthorization(t *testing.T) {
	now := time.Now()
	m := projectionMatcher(time.Minute)
	m.matchNonRU = true
	m.acceptResponse("test.example", &asyncDNSClassifierResponse{State: "ready", Route: "other", NonRuConfirmed: true, TTLMillis: 1000, StaleTTLMillis: 10000}, now, now)
	// Avoid starting workers in this pure deadline fixture.
	e := m.cache["test.example"]
	e.refreshAt = now.Add(time.Hour)
	m.putEntry("test.example", e)
	if got, _ := m.lookup("test.example", now.Add(999*time.Millisecond)); !got {
		t.Fatal("fresh proof lost")
	}
	if got, found := m.lookup("test.example", now.Add(time.Second)); got || !found {
		t.Fatal("stale grace authorized foreign route")
	}
}

func TestAsyncDNSNonRURefreshRevokesProofOnMixedAnswers(t *testing.T) {
	now := time.Now()
	m := projectionMatcher(time.Minute)
	m.matchNonRU = true
	m.acceptResponse("test.example", &asyncDNSClassifierResponse{State: "ready", Route: "other", NonRuConfirmed: true, TTLMillis: 1000, Generation: "fill-1"}, now, now)
	later := now.Add(time.Millisecond)
	m.acceptResponse("test.example", &asyncDNSClassifierResponse{State: "ready", Route: "other", TTLMillis: 1000, Generation: "fill-2"}, later, later)
	if got, _ := m.lookup("test.example", later); got {
		t.Fatal("new mixed/unknown fill retained old nonRU proof")
	}
}

func TestAsyncDNSNonRUHTTPFailuresAndLegacyBodiesDoNotGrantRoute(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
		want       bool
	}{
		{"new-proof", `{"state":"ready","route":"other","nonRuConfirmed":true,"ttlMillis":5000}`, 200, true},
		{"old-body", `{"state":"ready","route":"other","ttlMillis":5000}`, 200, false},
		{"wrong-proof-type", `{"state":"ready","route":"other","nonRuConfirmed":"true","ttlMillis":5000}`, 200, false},
		{"http-error", `{"state":"ready","route":"other","nonRuConfirmed":true,"ttlMillis":5000}`, 503, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) }))
			defer server.Close()
			m := newV2Matcher(t, &AsyncDnsRouteConfig{Endpoint: server.URL, MatchDecision: "non_ru", RouteWaitMillis: 100})
			if got := m.Apply(swrContext("test.example")); got != tc.want {
				t.Fatalf("route=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestAsyncDNSNonRUSnapshotPreservesProofAndRejectsLegacyAuthority(t *testing.T) {
	for _, proof := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "proven"}[proof], func(t *testing.T) {
			config := &AsyncDnsRouteConfig{Endpoint: "http://127.0.0.1:1", MatchDecision: "non_ru", SnapshotPath: filepath.Join(t.TempDir(), "cache", "l1.json"), SnapshotCompatibilityId: "test-view"}
			m := newV2Matcher(t, config)
			now := time.Now()
			m.mu.Lock()
			m.acceptResponse("saved.example", &asyncDNSClassifierResponse{State: "ready", Route: "other", NonRuConfirmed: proof, TTLMillis: 5000}, now, now)
			m.mu.Unlock()
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			next := newV2Matcher(t, config)
			if got := next.Apply(swrContext("saved.example")); got != proof {
				t.Fatalf("restored route=%v want=%v", got, proof)
			}
			if next.Stats().Requests != 0 {
				t.Fatal("snapshot unexpectedly refetched")
			}
		})
	}
	now := time.Now()
	payload := asyncDNSSnapshotPayload{Version: asyncDNSSnapshotVersion, Identity: "test", SavedAt: now, Entries: []asyncDNSSnapshotEntry{{Domain: "test.example", RouteRU: true, NonRuConfirmed: true, FreshUntil: now.Add(time.Second), HardUntil: now.Add(time.Second), ServerHardUntil: now.Add(time.Second), LastUsed: now}}}
	encoded, err := encodeAsyncDNSSnapshot(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeAsyncDNSSnapshot(encoded, "test", now, 8, time.Minute); err == nil {
		t.Fatal("contradictory snapshot proof accepted")
	}
}

func TestAsyncDNSMatchDecisionValidationAndProtobuf(t *testing.T) {
	for _, mode := range []string{"", "ru", "non_ru"} {
		cfg := &AsyncDnsRouteConfig{Endpoint: "http://127.0.0.1:1", MatchDecision: mode}
		data, err := proto.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		restored := new(AsyncDnsRouteConfig)
		if err = proto.Unmarshal(data, restored); err != nil || restored.GetMatchDecision() != mode {
			t.Fatal("protobuf decision lost")
		}
		m := newV2Matcher(t, restored)
		if m.matchNonRU != (mode == "non_ru") {
			t.Fatal("wrong matcher mode")
		}
	}
	for _, mode := range []string{"other", "NON_RU", "!ru", "non_ru "} {
		if _, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: "http://127.0.0.1:1", MatchDecision: mode}); err == nil {
			t.Fatal("invalid decision accepted")
		}
	}
}
