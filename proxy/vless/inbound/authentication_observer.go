package inbound

import (
	"context"
	"encoding/hex"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless"
)

// This wrapper is per Process call; context is never stored on the shared
// validator. Only Get(nil) observes rejection. All other validator semantics,
// including VLESS route-byte normalization, stay with the actual owner.
type observedValidator struct {
	vless.Validator
	ctx      context.Context
	observer routing.InboundAuthenticationObserver
}

func (v observedValidator) Get(id uuid.UUID) *protocol.MemoryUser {
	user := v.Validator.Get(id)
	if user == nil {
		normalized := vless.ProcessUUID(id)
		routing.NotifyInboundAuthenticationRejected(v.ctx, v.observer, "vless", hex.EncodeToString(normalized[:]))
	}
	return user
}

func withAuthenticationObserver(ctx context.Context, validator vless.Validator, dispatcher routing.Dispatcher) vless.Validator {
	if o, ok := dispatcher.(routing.InboundAuthenticationObserver); ok {
		return observedValidator{validator, ctx, o}
	}
	return validator
}
