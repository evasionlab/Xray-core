package reality

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	goreality "github.com/xtls/reality"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
)

type handshakePolicy struct{ timeout time.Duration }

func (*handshakePolicy) Type() interface{}        { return policy.ManagerType() }
func (*handshakePolicy) Start() error             { return nil }
func (*handshakePolicy) Close() error             { return nil }
func (*handshakePolicy) ForSystem() policy.System { return policy.System{} }
func (p *handshakePolicy) ForLevel(uint32) policy.Session {
	s := policy.SessionDefault()
	s.Timeouts.Handshake = p.timeout
	return s
}

func policyContext(t *testing.T, timeout time.Duration) context.Context {
	t.Helper()
	instance := new(core.Instance)
	if err := instance.AddFeature(&handshakePolicy{timeout}); err != nil {
		t.Fatal(err)
	}
	return context.WithValue(context.Background(), core.XrayKey(1), instance)
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	s, err := l.AcceptTCP()
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

func record(payload []byte) []byte {
	b := []byte{22, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(b[3:], uint16(len(payload)))
	return append(b, payload...)
}

func TestServerBoundsSilentAndPartialClientHelloBeforeDial(t *testing.T) {
	for name, prefix := range map[string][]byte{"silent": nil, "partial header": {22, 3}, "partial body": {22, 3, 1, 0, 8, 1}, "fragmented partial hello": record([]byte{1, 0, 0, 8, 3})} {
		t.Run(name, func(t *testing.T) {
			client, server := tcpPair(t)
			var dials atomic.Int32
			config := &goreality.Config{DialContext: func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("unexpected camouflage dial")
			}}
			done := make(chan error, 1)
			ctx := policyContext(t, 100*time.Millisecond)
			go func() { _, err := ServerWithContext(ctx, server, config); done <- err }()
			if len(prefix) > 0 {
				if _, err := client.Write(prefix); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatalf("expected configured handshake timeout, got %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("pre-auth connection did not terminate")
			}
			if dials.Load() != 0 {
				t.Fatalf("dialed camouflage %d times before complete ClientHello", dials.Load())
			}
		})
	}
}

func TestReadClientHelloPrefixFragmentationAndReplay(t *testing.T) {
	hello := []byte{1, 0, 0, 7, 3, 3, 0, 0, 0, 0, 0}
	for _, split := range []int{1, 3, 4, 7, 10} {
		wire := append(record(hello[:split]), record(hello[split:])...)
		r := bytes.NewReader(append(append([]byte(nil), wire...), 9, 8, 7))
		prefix, err := readClientHelloPrefix(r)
		if err != nil || !bytes.Equal(prefix, wire) {
			t.Fatalf("split %d: %x, %v", split, prefix, err)
		}
		if r.Len() != 3 {
			t.Fatalf("read beyond hello: %d remaining", r.Len())
		}
	}
	for _, wire := range [][]byte{[]byte("GET /"), {22, 2, 0, 0, 1}, {22, 3, 1, 255, 255}} {
		prefix, err := readClientHelloPrefix(bytes.NewReader(wire))
		if err != nil || !bytes.Equal(prefix, wire[:len(prefix)]) {
			t.Fatalf("changed malformed/plaintext prefix: %x %v", prefix, err)
		}
	}
}

func testTLSBackend(t *testing.T) (string, *ecdh.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"fallback.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	go func() {
		for {
			raw, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer raw.Close(); c := tls.Server(raw, cfg); io.Copy(c, c) }()
		}
	}()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return l.Addr().String(), private
}

func serverConfig(address string, private *ecdh.PrivateKey) *goreality.Config {
	return &goreality.Config{Type: "tcp", Dest: address, DialContext: (&net.Dialer{}).DialContext, PrivateKey: private.Bytes(), ServerNames: map[string]bool{"fallback.test": true}, ShortIds: map[[8]byte]bool{{}: true}, SessionTicketsDisabled: true}
}

func TestServerPreservesLongLivedTLSFallback(t *testing.T) {
	address, private := testTLSBackend(t)
	client, server := tcpPair(t)
	ctx := policyContext(t, 150*time.Millisecond)
	done := make(chan error, 1)
	go func() { _, err := ServerWithContext(ctx, server, serverConfig(address, private)); done <- err }()
	c := tls.Client(client, &tls.Config{ServerName: "fallback.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(350 * time.Millisecond)
	client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("fallback stays open")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("fallback stays open"))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "fallback stays open" {
		t.Fatalf("changed bytes %q", got)
	}
	c.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("fallback did not release")
	}
}

func TestServerPreservesAuthenticatedREALITYAfterBudget(t *testing.T) {
	address, private := testTLSBackend(t)
	cfg := serverConfig(address, private)
	for _, alpn := range []string{"0", "1", "2"} {
		key := address + " fallback.test " + alpn
		goreality.GlobalPostHandshakeRecordsLens.Store(key, []int{})
		t.Cleanup(func() { goreality.GlobalPostHandshakeRecordsLens.Delete(key) })
	}
	client, server := tcpPair(t)
	serverCtx := policyContext(t, 500*time.Millisecond)
	done := make(chan error, 1)
	go func() {
		c, err := ServerWithContext(serverCtx, server, cfg)
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		_, err = io.Copy(c, c)
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := UClient(client, &Config{ServerName: "fallback.test", Fingerprint: "chrome", PublicKey: private.PublicKey().Bytes(), ShortId: make([]byte, 8)}, ctx, xnet.TCPDestination(xnet.DomainAddress("fallback.test"), 443))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("authenticated stays open")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("authenticated stays open"))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "authenticated stays open" {
		t.Fatalf("changed bytes %q", got)
	}
	c.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authenticated did not release")
	}
}

func TestServerBoundsCamouflageDialByRemainingBudget(t *testing.T) {
	client, server := tcpPair(t)
	var dials atomic.Int32
	cfg := &goreality.Config{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		dials.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	done := make(chan error, 1)
	ctx := policyContext(t, 150*time.Millisecond)
	go func() { _, err := ServerWithContext(ctx, server, cfg); done <- err }()
	time.Sleep(50 * time.Millisecond)
	if _, err := client.Write(record([]byte{1, 0, 0, 0})); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("missing dial deadline error")
		}
	case <-time.After(time.Second):
		t.Fatal("dial ignored remaining budget")
	}
	if dials.Load() != 1 {
		t.Fatalf("expected one dial, got %d", dials.Load())
	}
}
