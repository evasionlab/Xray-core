package routing

import (
	"context"
	"errors"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/transport"
)

// InboundDispatcherWrapper is an optional per-Instance dispatcher extension.
// It wraps the authenticated outer inbound path before mux consumes its parent
// link. Mux children still use the installed Dispatcher. The default dispatcher
// does not implement this interface and its behavior is unchanged.
type InboundDispatcherWrapper interface {
	WrapInboundDispatcher(inner Dispatcher) Dispatcher
}

func WrapInboundDispatcher(installed, inner Dispatcher) (Dispatcher, error) {
	if wrapper, ok := installed.(InboundDispatcherWrapper); ok {
		result := wrapper.WrapInboundDispatcher(inner)
		if result == nil {
			return nil, errors.New("inbound dispatcher wrapper returned nil")
		}
		return result, nil
	}
	return inner, nil
}

// InboundSessionLifecycle is an optional per-Instance stream lifecycle hook.
// Begin runs after Core installs Inbound{Tag, Conn}, before proxy authentication.
// A consumer may lazily admit the authenticated parent on its first dispatch.
// Core defers end until Process returns (including errors); the hook must return
// a nonnil context and cleanup. Native datagram workers are outside this scope.
// The default dispatcher does not implement this interface.
//
// The returned context must retain Core's existing inbound/content state. This
// hook grants no authentication by itself and must not admit unauthenticated
// connections merely because Begin was called.
type InboundSessionLifecycle interface {
	BeginInboundSession(context.Context) (context.Context, func())
}

// Dispatcher is a feature that dispatches inbound requests to outbound handlers based on rules.
// Dispatcher is required to be registered in a Xray instance to make Xray function properly.
//
// xray:api:stable
type Dispatcher interface {
	features.Feature

	// Dispatch returns a Ray for transporting data for the given request.
	Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error)
	DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error
}

// DispatcherType returns the type of Dispatcher interface. Can be used to implement common.HasType.
//
// xray:api:stable
func DispatcherType() interface{} {
	return (*Dispatcher)(nil)
}
