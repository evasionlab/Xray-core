package routing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// InboundAuthenticationObserver is an optional per-Instance observation hook.
// It runs only at the credential validator's explicit unknown-user decision,
// before dispatch/device/accounting. It cannot authorize a credential, override
// rejection or infer an expected subscription result. It must not log credential
// material or this private authenticator digest. Wrappers must explicitly forward
// this interface; absent observers preserve the existing behavior.
type InboundAuthenticationObserver interface {
	InboundAuthenticationRejected(ctx context.Context, protocol, authenticatorSHA256 string)
}

// NotifyInboundAuthenticationRejected requires a complete canonical authenticator:
// VLESS is hex32 of ProcessUUID(raw UUID), Trojan is the lowercase wire SHA224
// hex56. Decode/handshake/truncation/protocol errors never become auth verdicts.
func NotifyInboundAuthenticationRejected(ctx context.Context, observer any, protocol, authenticator string) {
	size := 0
	switch protocol {
	case "vless":
		size = 32
	case "trojan":
		size = 56
	default:
		return
	}
	if len(authenticator) != size {
		return
	}
	b, e := hex.DecodeString(authenticator)
	if e != nil || hex.EncodeToString(b) != authenticator {
		return
	}
	if o, ok := observer.(InboundAuthenticationObserver); ok {
		h := sha256.Sum256([]byte("vpn.runtime.authenticator.v1\n" + protocol + "\n" + authenticator))
		o.InboundAuthenticationRejected(ctx, protocol, hex.EncodeToString(h[:]))
	}
}
