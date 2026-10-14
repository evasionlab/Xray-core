package trojan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	gonet "net"
	"testing"
	"time"

	corepolicy "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type authObserver struct {
	count int
	proof string
}

func (*authObserver) Type() interface{} { return routing.DispatcherType() }
func (*authObserver) Start() error      { return nil }
func (*authObserver) Close() error      { return nil }
func (*authObserver) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	panic("unexpected dispatch")
}

func (*authObserver) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	panic("unexpected dispatch")
}

func (o *authObserver) InboundAuthenticationRejected(_ context.Context, p, proof string) {
	if p != "trojan" {
		panic("wrong protocol")
	}
	o.count++
	o.proof = proof
}

func TestActualTrojanValidatorRejectDistinctFromProtocolFailure(t *testing.T) {
	h := sha256.Sum224([]byte("retained-password"))
	auth := hex.EncodeToString(h[:])
	for _, scenario := range []struct {
		name, frame string
		installed   bool
		want        int
	}{{"unknown", auth + "\r\n", false, 1}, {"known-truncated-header", auth + "\r\n", true, 0}, {"invalid-CRLF", auth + "\rx", false, 0}, {"noncanonical-authenticator", "Z" + auth[1:] + "\r\n", false, 0}, {"short", "hello", false, 0}} {
		t.Run(scenario.name, func(t *testing.T) {
			manager, e := corepolicy.New(context.Background(), &corepolicy.Config{})
			if e != nil {
				t.Fatal(e)
			}
			validator := new(Validator)
			if scenario.installed {
				account, e := (&Account{Password: "retained-password"}).AsAccount()
				if e != nil {
					t.Fatal(e)
				}
				if e = validator.Add(&protocol.MemoryUser{Email: "retained", Account: account}); e != nil {
					t.Fatal(e)
				}
			}
			server := &Server{policyManager: manager, validator: validator}
			observer := new(authObserver)
			accepted, client := gonet.Pipe()
			defer accepted.Close()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			done := make(chan struct{})
			go func() { defer close(done); _, _ = client.Write([]byte(scenario.frame)); client.Close() }()
			e = server.Process(context.Background(), net.Network_TCP, accepted, observer)
			if e == nil {
				t.Fatal("invalid request accepted")
			}
			<-done
			if observer.count != scenario.want {
				t.Fatalf("authverdict=%d want=%d", observer.count, scenario.want)
			}
			if scenario.want == 1 {
				proof := sha256.Sum256([]byte("vpn.runtime.authenticator.v1\ntrojan\n" + auth))
				if observer.proof != hex.EncodeToString(proof[:]) {
					t.Fatal("wrong actual wire proof")
				}
			}
		})
	}
}
