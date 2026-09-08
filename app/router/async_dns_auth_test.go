package router

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func setAsyncDNSTestToken(t *testing.T, token string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bearer")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_ASYNC_DNS_BEARER_TOKEN_FILE", path)
}

func TestAsyncDNSBearerFileValidation(t *testing.T) {
	for _, tc := range []struct{ name, token string }{
		{"empty", "\n"}, {"header injection", "secret\r\nX-Foo: bar"}, {"oversized", strings.Repeat("a", 4097)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setAsyncDNSTestToken(t, tc.token)
			if _, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: "https://example.com"}); err == nil {
				t.Fatal("invalid configured token must reject matcher")
			}
		})
	}
	for _, path := range []string{filepath.Join(t.TempDir(), "missing"), t.TempDir()} {
		t.Setenv("XRAY_ASYNC_DNS_BEARER_TOKEN_FILE", path)
		if _, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: "https://example.com"}); err == nil {
			t.Fatal("unreadable configured token must reject matcher")
		} else if strings.Contains(err.Error(), path) {
			t.Fatal("error disclosed local secret path")
		}
	}
}

func TestAsyncDNSBearerHTTPS(t *testing.T) {
	setAsyncDNSTestToken(t, "test-token\n")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing bearer authorization")
		}
		_, _ = w.Write([]byte(`{"state":"ready","route":"ru","ttlMillis":1000}`))
	}))
	defer server.Close()
	m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.client.Transport = server.Client().Transport
	response, err := m.fetch("example.com")
	if err != nil || response.Route != "ru" {
		t.Fatalf("authenticated classifier request failed: %v", err)
	}
}

func TestAsyncDNSBearerRefusesHTTPAndRedirects(t *testing.T) {
	setAsyncDNSTestToken(t, "test-token")
	var leaked atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
	}))
	defer destination.Close()
	if _, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: destination.URL}); err == nil {
		t.Fatal("authenticated HTTP endpoint accepted")
	}
	for _, status := range []int{301, 302, 303, 307, 308} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, destination.URL, status)
		}))
		m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: server.URL})
		if err != nil {
			t.Fatal(err)
		}
		m.client.Transport = server.Client().Transport
		if _, err := m.fetch("example.com"); err == nil {
			t.Error("redirect must fail classification")
		}
		m.Close()
		server.Close()
	}
	if leaked.Load() != 0 {
		t.Fatal("authenticated classifier followed redirect")
	}
}

func TestAsyncDNSUnsetTokenRetainsAnonymousHTTP(t *testing.T) {
	t.Setenv("XRAY_ASYNC_DNS_BEARER_TOKEN_FILE", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("unexpected authorization")
		}
		_, _ = w.Write([]byte(`{"state":"ready","route":"other","ttlMillis":1000}`))
	}))
	defer server.Close()
	m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := m.fetch("example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestAsyncDNSBearerExactOverlay(t *testing.T) {
	setAsyncDNSTestToken(t, "test-token")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer test-token" || r.URL.Path != "/v1/classify" {
			t.Error("overlay request lost authorization or endpoint")
		}
		_, _ = w.Write([]byte(`{"state":"ready","route":"ru","ttlMillis":1000}`))
	}))
	defer server.Close()
	endpoint := server.URL + "/v1/classify"
	t.Setenv("XRAY_ASYNC_DNS_OVERLAY_ENDPOINT", endpoint)
	m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if transport, ok := m.client.Transport.(*http.Transport); !ok || transport.Proxy != nil {
		t.Fatal("overlay must bypass environment proxies")
	}
	response, err := m.fetch("example.com")
	if err != nil || response.Route != "ru" || requests.Load() != 1 {
		t.Fatalf("overlay request failed: %v", err)
	}
	for _, other := range []string{server.URL, endpoint + "?q=1", endpoint + "/other", "http://127.0.0.2:8090/v1/classify"} {
		if matcher, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: other}); err == nil {
			matcher.Close()
			t.Errorf("accepted endpoint outside exact overlay pin: %s", other)
		}
	}
	// Recheck the endpoint at the credential boundary, even after construction.
	m.endpoint = server.URL + "/other"
	if _, err := m.fetch("example.com"); err == nil || requests.Load() != 1 {
		t.Fatal("changed endpoint leaked bearer")
	}
}

func TestAsyncDNSOverlayValidation(t *testing.T) {
	setAsyncDNSTestToken(t, "test-token")
	for _, endpoint := range []string{
		"http://classifier.internal:8090/v1/classify", "http://100.75.19.209/v1/classify",
		"https://100.75.19.209:8090/v1/classify", "http://user@100.75.19.209:8090/v1/classify",
		"http://100.75.19.209:8090/v1/classify?q=1", "http://100.75.19.209:8090/v1/classify#fragment", "invalid",
	} {
		t.Setenv("XRAY_ASYNC_DNS_OVERLAY_ENDPOINT", endpoint)
		if m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: "https://example.com"}); err == nil {
			m.Close()
			t.Errorf("accepted invalid overlay pin: %s", endpoint)
		}
	}
	t.Setenv("XRAY_ASYNC_DNS_OVERLAY_ENDPOINT", "http://100.75.19.209:8090/v1/classify")
	t.Setenv("XRAY_ASYNC_DNS_BEARER_TOKEN_FILE", "")
	if m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: "http://100.75.19.209:8090/v1/classify"}); err == nil {
		m.Close()
		t.Fatal("overlay accepted missing bearer token")
	}
}

func TestAsyncDNSOverlayRefusesRedirects(t *testing.T) {
	setAsyncDNSTestToken(t, "test-token")
	var leaked atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
	}))
	defer destination.Close()
	for _, status := range []int{301, 302, 303, 307, 308} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, destination.URL, status)
		}))
		t.Setenv("XRAY_ASYNC_DNS_OVERLAY_ENDPOINT", server.URL)
		m, err := NewAsyncDNSRouteMatcher(&AsyncDnsRouteConfig{Endpoint: server.URL})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.fetch("example.com"); err == nil {
			t.Error("overlay redirect must fail classification")
		}
		m.Close()
		server.Close()
	}
	if leaked.Load() != 0 {
		t.Fatal("overlay classifier followed redirect")
	}
}
