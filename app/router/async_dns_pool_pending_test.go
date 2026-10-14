package router

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

const poolPending = `{"state":"pending","retryAfterMillis":5000}`

func poolReply(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }
}

func TestAsyncDNSPoolPendingPrefersClassification(t *testing.T) {
	for _, body := range []string{poolReady, `{"state":"ready","route":"other","ttlMillis":5000}`, `{"state":"stale","route":"ru","staleTtlMillis":5000}`} {
		t.Run(body, func(t *testing.T) {
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, poolReply(poolPending), poolReply(body), func(w http.ResponseWriter, r *http.Request) { t.Error("classification caused surplus request") })
			response, err := m.fetchContext(context.Background(), "pending-ready.example")
			if err != nil || response == nil || response.State == "pending" {
				t.Fatalf("pending hid classification: %+v %v", response, err)
			}
			s := m.pool.endpointStats()
			if s[0].Pending != 1 || s[0].Successes != 1 || s[1].Successes != 1 || s[2].Started != 0 || m.Stats().PoolAttempts != 2 {
				t.Fatalf("attempt accounting: %+v", s)
			}
			if m.pool.states[0].failures != 0 {
				t.Fatal("valid pending penalized transport health")
			}
		})
	}
}

func TestAsyncDNSPoolPendingAllSequentialPreservesRetry(t *testing.T) {
	var active, peak atomic.Int32
	pending := func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		io.WriteString(w, poolPending)
	}
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, pending, pending, pending, pending, pending, pending)
	response, err := m.fetchContext(context.Background(), "all-pending.example")
	if err != nil || response == nil || response.State != "pending" || response.RetryAfterMillis != 5000 || peak.Load() != 1 || m.Stats().PoolAttempts != 6 {
		t.Fatalf("pending retry/fanout changed: %+v %v peak=%d stats=%+v", response, err, peak.Load(), m.Stats())
	}
	for _, s := range m.pool.endpointStats() {
		if s.Pending != 1 || s.Successes != 1 || s.HedgeStarts != 0 || s.Timeout != 0 {
			t.Fatalf("pending accounting changed: %+v", s)
		}
	}
}

func TestAsyncDNSPoolPendingDeadlineRetainsResponse(t *testing.T) {
	stall := func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
	m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, poolReply(poolPending), stall, stall)
	started := time.Now()
	response, err := m.fetchContext(context.Background(), "pending-stalls.example")
	elapsed := time.Since(started)
	if err != nil || response == nil || response.State != "pending" || response.RetryAfterMillis != 5000 || elapsed < 130*time.Millisecond || elapsed > 300*time.Millisecond {
		t.Fatalf("lost pending/shared deadline: %+v %v elapsed=%s", response, err, elapsed)
	}
	s := m.pool.endpointStats()
	if s[0].Pending != 1 || s[1].Timeout != 1 || s[2].Timeout != 1 || s[1].WinnerCanceled != 0 || s[2].WinnerCanceled != 0 {
		t.Fatalf("real timeout hidden: %+v", s)
	}
	if m.pool.states[1].failures != 1 || m.pool.states[2].failures != 1 {
		t.Fatal("peer timeouts lost health penalty")
	}
}

func TestAsyncDNSPoolPendingTerminalPeerOverridesPending(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{{401, ""}, {403, ""}, {429, ""}, {500, ""}, {200, "{"}, {200, `{"state":"broken"}`}, {200, `{"state":"pending","route":"ru"}`}} {
		t.Run(http.StatusText(tc.status)+tc.body, func(t *testing.T) {
			terminal := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) }
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, poolReply(poolPending), terminal, func(w http.ResponseWriter, r *http.Request) { t.Error("terminal peer fanned out") })
			response, err := m.fetchContext(context.Background(), "pending-terminal.example")
			if (err == nil && classifyAsyncDNSResponse(response, 0) != asyncDNSResponseInvalid) || m.Stats().PoolAttempts != 2 {
				t.Fatalf("terminal hidden by pending: %+v %v", response, err)
			}
		})
	}
}

func TestAsyncDNSPoolPendingCallerCancellationAndWinnerDrain(t *testing.T) {
	for _, winner := range []bool{false, true} {
		t.Run(map[bool]string{false: "caller", true: "ready"}[winner], func(t *testing.T) {
			started := make(chan struct{})
			var active atomic.Int32
			stall := func(w http.ResponseWriter, r *http.Request) {
				active.Add(1)
				defer active.Add(-1)
				close(started)
				<-r.Context().Done()
			}
			third := func(w http.ResponseWriter, r *http.Request) {
				if winner {
					io.WriteString(w, poolReady)
				} else {
					<-r.Context().Done()
				}
			}
			m := newAsyncDNSPoolTestMatcher(t, &AsyncDnsRouteConfig{RequestTimeoutMillis: 150}, poolReply(poolPending), stall, third)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if !winner {
				go func() { <-started; cancel() }()
			}
			response, err := m.fetchContext(ctx, "pending-cancel.example")
			s := m.pool.endpointStats()
			if winner {
				if err != nil || response == nil || response.State != "ready" || s[1].WinnerCanceled != 1 {
					t.Fatalf("ready/drain: %+v %v stats=%+v", response, err, s)
				}
			} else {
				if !errors.Is(err, context.Canceled) || response != nil || s[1].Canceled != 1 {
					t.Fatalf("caller cancellation hidden: %+v %v stats=%+v", response, err, s)
				}
			}
			if m.pool.states[1].failures != 0 {
				t.Fatal("cancellation penalized endpoint")
			}
			deadline := time.Now().Add(time.Second)
			for active.Load() != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if active.Load() != 0 {
				t.Fatal("canceled HTTP request not drained")
			}
		})
	}
}
