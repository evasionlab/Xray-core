package inbound_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// Exercise the complete configured Core -> inbound handler -> tcpWorker ->
// transport listener path. Injecting a Core context directly into ListenTCP
// cannot detect a worker that replaces its own context with Background.
func TestREALITYCoreWorkerUsesConfiguredHandshakeBudget(t *testing.T) {
	camouflage := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	camouflage.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	camouflage.StartTLS()
	defer camouflage.Close()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	defer reservation.Close()
	raw, err := json.Marshal(map[string]any{
		"log":    map[string]any{"loglevel": "none"},
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{"handshake": 4, "connIdle": 1800, "uplinkOnly": 2, "downlinkOnly": 4}}},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings": map[string]any{"clients": []any{map[string]any{"id": "11111111-1111-4111-8111-111111111111"}}, "decryption": "none"},
			"streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{
				"target": strings.TrimPrefix(camouflage.URL, "https://"), "serverNames": []string{"localhost"},
				"privateKey": base64.RawURLEncoding.EncodeToString(key.Bytes()), "shortIds": []string{"0123456789abcdef"},
			}},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	config, err := core.LoadConfig("json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	server, err := core.NewWithContext(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	configured := server.GetFeature(policy.ManagerType()).(policy.Manager).ForLevel(0).Timeouts
	if configured.Handshake != 4*time.Second || configured.ConnectionIdle != 1800*time.Second {
		t.Fatalf("fixture lost configured admission/idle policy: %+v", configured)
	}
	reservation.Close()
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	type result struct {
		name    string
		elapsed time.Duration
		bytes   int
		err     error
	}
	cases := map[string][]byte{"empty": nil, "partial header": {22, 3}, "partial record": {22, 3, 1, 0, 8, 1}}
	results := make(chan result, len(cases))
	for name, prefix := range cases {
		go func() {
			client, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				results <- result{name: name, err: err}
				return
			}
			defer client.Close()
			started := time.Now()
			if len(prefix) != 0 {
				if _, err = client.Write(prefix); err != nil {
					results <- result{name: name, err: err}
					return
				}
			}
			client.SetReadDeadline(started.Add(7 * time.Second))
			n, err := client.Read(make([]byte, 1))
			results <- result{name: name, elapsed: time.Since(started), bytes: n, err: err}
		}()
	}
	for range cases {
		r := <-results
		if timeout, ok := r.err.(net.Error); ok && timeout.Timeout() {
			t.Errorf("%s: actual Core worker ignored configured 4s budget; still open after %v: %v", r.name, r.elapsed, r.err)
			continue
		}
		if r.bytes != 0 || r.err != io.EOF {
			t.Errorf("%s: expected admission close, got n=%d err=%v", r.name, r.bytes, r.err)
			continue
		}
		if r.elapsed < 3500*time.Millisecond || r.elapsed > 6*time.Second {
			t.Errorf("%s: close at %v does not match configured 4s handshake budget", r.name, r.elapsed)
		} else {
			t.Logf("%s closed after %v with actual configured 4s handshake budget", r.name, r.elapsed)
		}
	}
}
