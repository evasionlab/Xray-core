package inbound

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
)

type rejected struct {
	count int
	proof string
	ctx   context.Context
}

func (o *rejected) InboundAuthenticationRejected(ctx context.Context, p, proof string) {
	if p != "vless" {
		panic("unexpected protocol")
	}
	o.count++
	o.proof = proof
	o.ctx = ctx
}

func TestActualHeaderValidatorRejectionObserver(t *testing.T) {
	id := uuid.New()
	validator := new(vless.MemoryValidator)
	o := new(rejected)
	ctx := context.WithValue(context.Background(), struct{}{}, "socket")
	wire := append([]byte{0}, id.Bytes()...)
	_, _, _, _, e := encoding.DecodeRequestHeader(false, buf.New(), bytes.NewReader(wire), observedValidator{validator, ctx, o})
	if e == nil || o.count != 1 || o.ctx != ctx {
		t.Fatal("missing typed validator verdict", e, o.count)
	}
	normalized := vless.ProcessUUID(id)
	h := sha256.Sum256([]byte("vpn.runtime.authenticator.v1\nvless\n" + hex.EncodeToString(normalized[:])))
	if o.proof != hex.EncodeToString(h[:]) {
		t.Fatal("not actual validator id")
	}
	for _, invalid := range [][]byte{{}, {9}, {0, 1, 2, 3}} {
		_, _, _, _, e = encoding.DecodeRequestHeader(false, buf.New(), bytes.NewReader(invalid), observedValidator{validator, ctx, o})
		if e == nil || o.count != 1 {
			t.Fatal("read/version error became authentication rejection")
		}
	}
	user := &protocol.MemoryUser{Email: "fixture", Account: &vless.MemoryAccount{ID: protocol.NewID(id)}}
	if e = validator.Add(user); e != nil {
		t.Fatal(e)
	}
	if observedValidatorValue := (observedValidator{validator, ctx, o}).Get(id); observedValidatorValue != user || o.count != 1 {
		t.Fatal("existing credential changed")
	}
}
