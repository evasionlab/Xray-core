package routing_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type dispatcher struct{ calls int }

func (*dispatcher) Type() interface{} { return routing.DispatcherType() }
func (*dispatcher) Start() error      { return nil }
func (*dispatcher) Close() error      { return nil }
func (*dispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, nil
}
func (d *dispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	d.calls++
	return nil
}

type wrapped struct {
	dispatcher
	inner     routing.Dispatcher
	wraps     int
	nilResult bool
}

func (w *wrapped) WrapInboundDispatcher(inner routing.Dispatcher) routing.Dispatcher {
	w.wraps++
	w.inner = inner
	if w.nilResult {
		return nil
	}
	return w
}
func (w *wrapped) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	w.calls++
	return w.inner.DispatchLink(ctx, dest, link)
}
func TestInboundWrapperIsPerInstanceAndDelegatesMuxParent(t *testing.T) {
	inner := new(dispatcher)
	plain := new(dispatcher)
	result, err := routing.WrapInboundDispatcher(plain, inner)
	if err != nil || result != inner {
		t.Fatalf("default dispatcher changed result=%v err=%v", result, err)
	}
	owner := new(wrapped)
	result, err = routing.WrapInboundDispatcher(owner, inner)
	if err != nil {
		t.Fatal(err)
	}
	destination := net.TCPDestination(net.DomainAddress("v1.mux.cool"), 9527)
	if err := result.DispatchLink(context.Background(), destination, &transport.Link{}); err != nil {
		t.Fatal(err)
	}
	if owner.wraps != 1 || owner.calls != 1 || inner.calls != 1 {
		t.Fatalf("outer/mux calls=%d/%d/%d", owner.wraps, owner.calls, inner.calls)
	}
	// An unrelated Core keeps its own dispatcher, with no global hook.
	other := new(dispatcher)
	result, err = routing.WrapInboundDispatcher(plain, other)
	if err != nil || result != other || owner.wraps != 1 {
		t.Fatal("wrapper leaked to another instance")
	}
	owner.nilResult = true
	if _, err := routing.WrapInboundDispatcher(owner, inner); err == nil {
		t.Fatal("invalid wrapper silently bypassed admission")
	}
}
