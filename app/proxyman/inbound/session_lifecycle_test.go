package inbound

import (
	"context"
	stderrors "errors"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type (
	lifecycleKey   struct{}
	lifecycleProbe struct {
		begin func(context.Context) (context.Context, func())
	}
)

func (p *lifecycleProbe) BeginInboundSession(ctx context.Context) (context.Context, func()) {
	return p.begin(ctx)
}

type lifecycleProxy struct {
	process func(context.Context, net.Network, stat.Connection, routing.Dispatcher) error
}

func (p lifecycleProxy) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

func (p lifecycleProxy) Process(ctx context.Context, n net.Network, c stat.Connection, d routing.Dispatcher) error {
	return p.process(ctx, n, c, d)
}

type lifecycleConnection struct {
	stdnet.Conn
	network net.Network
}

func (c lifecycleConnection) LocalAddr() stdnet.Addr {
	if c.network == net.Network_UNIX {
		return &stdnet.UnixAddr{Name: "/tmp/core-lifecycle-local", Net: "unix"}
	}
	return &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 10443}
}

func (c lifecycleConnection) RemoteAddr() stdnet.Addr {
	if c.network == net.Network_UNIX {
		return &stdnet.UnixAddr{Name: "/tmp/core-lifecycle-peer", Net: "unix"}
	}
	return &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 20443}
}

// Exercise actual worker callbacks, not only the optional interface helper.
// The Core-defined lifetime covers authentication, dispatch and final Process
// return regardless of child rays; no timer or global connection map is added.
func TestStreamWorkerLifecycleOwnsExactProcessLifetime(t *testing.T) {
	for _, network := range []net.Network{net.Network_TCP, net.Network_UNIX} {
		for _, outcome := range []string{"success", "error", "cancel", "invalid-context", "invalid-end", "absent"} {
			t.Run(network.String()+"/"+outcome, func(t *testing.T) {
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				if outcome == "cancel" {
					cancel()
				}
				left, right := stdnet.Pipe()
				defer left.Close()
				defer right.Close()
				conn := lifecycleConnection{Conn: left, network: network}
				begun, ended, processed := 0, 0, 0
				var processContext context.Context
				var lifecycle routing.InboundSessionLifecycle
				if outcome != "absent" {
					lifecycle = &lifecycleProbe{begin: func(ctx context.Context) (context.Context, func()) {
						begun++
						incoming := session.InboundFromContext(ctx)
						if incoming == nil || incoming.Conn != conn || incoming.Tag != "managed" || incoming.User != nil {
							t.Fatalf("Begin before inbound state/after authentication: %+v", incoming)
						}
						if session.ContentFromContext(ctx) == nil {
							t.Fatal("sniffing content not installed before Begin")
						}
						end := func() {
							ended++
							if processContext != nil && outcome != "cancel" && processContext.Err() != nil {
								t.Fatal("Core canceled before Process scope cleanup")
							}
							if processed != 0 && incoming.User == nil {
								t.Fatal("cleanup lost authenticated inbound state")
							}
						}
						if outcome == "invalid-context" {
							return nil, end
						}
						if outcome == "invalid-end" {
							return ctx, nil
						}
						return context.WithValue(ctx, lifecycleKey{}, "scope"), end
					}}
				}
				p := lifecycleProxy{process: func(ctx context.Context, n net.Network, c stat.Connection, d routing.Dispatcher) error {
					processed++
					if n != network || c != conn {
						t.Fatal("Process connection changed")
					}
					if outcome != "absent" && (begun != 1 || ended != 0 || ctx.Value(lifecycleKey{}) != "scope") {
						t.Fatal("Process outside lifecycle context")
					}
					incoming := session.InboundFromContext(ctx)
					if incoming == nil || incoming.Tag != "managed" || incoming.Conn != conn {
						t.Fatal("Process lost Core inbound state")
					}
					incoming.User = &protocol.MemoryUser{Email: "principal"}
					processContext = ctx
					if outcome == "error" {
						return stderrors.New("injected authentication/dispatch failure")
					}
					if outcome == "cancel" {
						return ctx.Err()
					}
					return nil
				}}
				if network == net.Network_TCP {
					worker := tcpWorker{ctx: parent, address: net.LocalHostIP, port: 10443, tag: "managed", proxy: p, lifecycle: lifecycle}
					worker.callback(conn)
				} else {
					worker := dsWorker{ctx: parent, address: net.DomainAddress("/tmp/core-lifecycle-local"), tag: "managed", proxy: p, lifecycle: lifecycle}
					worker.callback(conn)
				}
				wantProcess, wantBegin, wantEnd := 1, 1, 1
				if outcome == "invalid-context" || outcome == "invalid-end" {
					wantProcess = 0
				}
				if outcome == "invalid-end" {
					wantEnd = 0
				}
				if outcome == "absent" {
					wantBegin, wantEnd = 0, 0
				}
				if processed != wantProcess || begun != wantBegin || ended != wantEnd {
					t.Fatalf("Process/Begin/end=%d/%d/%d want%d/%d/%d", processed, begun, ended, wantProcess, wantBegin, wantEnd)
				}
				if processContext != nil && processContext.Err() == nil {
					t.Fatal("Core did not cancel completed process")
				}
				right.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := right.Read(make([]byte, 1)); err == nil {
					t.Fatal("worker did not close connection")
				}
			})
		}
	}
}

func TestStreamProcessLifecycleCleansUpOnPanic(t *testing.T) {
	ended := 0
	hook := &lifecycleProbe{begin: func(ctx context.Context) (context.Context, func()) { return ctx, func() { ended++ } }}
	p := lifecycleProxy{process: func(context.Context, net.Network, stat.Connection, routing.Dispatcher) error {
		panic("injected Process panic")
	}}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("Process panic did not propagate")
			}
		}()
		_ = processStreamInbound(context.Background(), net.Network_TCP, nil, p, nil, hook)
	}()
	if ended != 1 {
		t.Fatalf("end calls=%d want1", ended)
	}
}
