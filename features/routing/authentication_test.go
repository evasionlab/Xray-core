package routing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

type rejectObserver struct {
	count           int
	protocol, proof string
	ctx             context.Context
}

func (o *rejectObserver) InboundAuthenticationRejected(ctx context.Context, protocol, proof string) {
	o.count++
	o.protocol = protocol
	o.proof = proof
	o.ctx = ctx
}

func TestAuthenticationObservationClosedAuthenticator(t *testing.T) {
	o := new(rejectObserver)
	ctx := context.WithValue(context.Background(), struct{}{}, "accepted-socket")
	valid := "11111111222200004444555555555555"
	NotifyInboundAuthenticationRejected(ctx, o, "vless", valid)
	h := sha256.Sum256([]byte("vpn.runtime.authenticator.v1\nvless\n" + valid))
	if o.count != 1 || o.ctx != ctx || o.proof != hex.EncodeToString(h[:]) {
		t.Fatal("wrong private verdict")
	}
	for _, v := range []struct{ p, a string }{{"unknown", valid}, {"vless", "notuuid"}, {"vless", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, {"trojan", valid}, {"trojan", "0000000000000000000000000000000000000000000000000000000z"}} {
		NotifyInboundAuthenticationRejected(ctx, o, v.p, v.a)
	}
	if o.count != 1 {
		t.Fatal("malformed authenticator became auth rejection")
	}
	NotifyInboundAuthenticationRejected(ctx, struct{}{}, "vless", valid)
}
