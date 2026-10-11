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
