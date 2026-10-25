package udp

import (
	"context"
	goerrors "errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/internal/forwardingdrain"
	"github.com/xtls/xray-core/transport"
)

type ResponseCallback func(ctx context.Context, packet *udp.Packet)

type connEntry struct {
	link        *transport.Link
	timer       *signal.ActivityTimer
	cancel      context.CancelFunc
	closed      bool
	drainToken  *forwardingdrain.Token
	drainDone   chan struct{}
	drainClosed atomic.Bool
	drainOnce   sync.Once
}

func (c *connEntry) Close() error {
	if c.drainToken != nil {
		c.terminate()
		c.timer.SetTimeout(0)
		return nil
	}
	c.timer.SetTimeout(0)
	return nil
}

func (c *connEntry) terminate() {
	if c.drainToken != nil {
		c.drainOnce.Do(func() {
			c.drainClosed.Store(true)
			c.cancel()
			common.Interrupt(c.link.Reader)
			common.Interrupt(c.link.Writer)
		})
		return
	}
	if c.closed {
		panic("terminate called more than once")
	}
	c.closed = true
	c.cancel()
	common.Interrupt(c.link.Reader)
	common.Interrupt(c.link.Writer)
}

type Dispatcher struct {
	sync.RWMutex
	conn         *connEntry
	dispatcher   routing.Dispatcher
	callback     ResponseCallback
	callClose    func() error
	closed       bool
	drainEntries map[*connEntry]struct{}
}

func NewDispatcher(dispatcher routing.Dispatcher, callback ResponseCallback) *Dispatcher {
	return &Dispatcher{
		dispatcher: dispatcher,
		callback:   callback,
	}
}

func (v *Dispatcher) RemoveRay() {
	v.Lock()
	defer v.Unlock()
	v.closed = true
	if v.conn != nil {
		v.conn.Close()
		v.conn = nil
	}
}

func (v *Dispatcher) getInboundRay(ctx context.Context, dest net.Destination) (*connEntry, error) {
	if forwardingdrain.FromContext(ctx) != nil && (!dest.IsValid() || !dest.Address.Family().IsIP()) {
		return nil, forwardingdrain.ErrUnsupported
	}
	v.Lock()
	defer v.Unlock()

	if v.closed {
		return nil, errors.New("dispatcher is closed")
	}

	if v.conn != nil {
		if v.conn.closed || (v.conn.drainToken != nil && v.conn.drainClosed.Load()) {
			v.conn = nil
		} else {
			return v.conn, nil
		}
	}

	errors.LogInfo(ctx, "establishing new connection for ", dest)

	ctx, cancel := context.WithCancel(ctx)

	link, err := v.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		cancel()
		return nil, errors.New("failed to dispatch request to ", dest).Base(err)
	}

	entry := &connEntry{
		link:   link,
		cancel: cancel,
	}

	if forwardingdrain.FromContext(ctx) != nil {
		token, e := forwardingdrain.Child(ctx, link.Reader, link.Writer)
		if e != nil {
			cancel()
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
			return nil, e
		}
		entry.drainToken = token
		entry.drainDone = make(chan struct{})
		if v.drainEntries == nil {
			v.drainEntries = map[*connEntry]struct{}{}
		}
		v.drainEntries[entry] = struct{}{}
	}
	entry.timer = signal.CancelAfterInactivity(ctx, entry.terminate, time.Minute)
	v.conn = entry
	if entry.drainToken == nil {
		go handleInput(ctx, entry, dest, v.callback, v.callClose)
	} else {
		go func() {
			handleInput(entry.drainToken.Context(ctx), entry, dest, v.callback, v.callClose)
			entry.drainToken.Done()
			v.Lock()
			delete(v.drainEntries, entry)
			close(entry.drainDone)
			v.Unlock()
		}()
	}
	return entry, nil
}

// CloseAndJoin is only used by the explicitly selected native drain branch.
// Callback completion is required; holding the dispatcher mutex through callback
// network I/O or waiting would deadlock. Normal RemoveRay behavior is unchanged.
func (v *Dispatcher) CloseAndJoin(ownedResources ...any) {
	v.Lock()
	v.closed = true
	entries := make([]*connEntry, 0, len(v.drainEntries))
	for e := range v.drainEntries {
		entries = append(entries, e)
	}
	v.Unlock()
	for _, r := range ownedResources {
		common.Close(r)
	}
	for _, e := range entries {
		e.Close()
	}
	for _, e := range entries {
		<-e.drainDone
	}
}

func (v *Dispatcher) Dispatch(ctx context.Context, destination net.Destination, payload *buf.Buffer) {
	// TODO: Add user to destString
	errors.LogDebug(ctx, "dispatch request to: ", destination)

	conn, err := v.getInboundRay(ctx, destination)
	if err != nil {
		errors.LogInfoInner(ctx, err, "failed to get inbound")
		if forwardingdrain.FromContext(ctx) != nil {
			payload.Release()
		}
		return
	}
	outputStream := conn.link.Writer
	if outputStream != nil {
		if err := outputStream.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
			errors.LogInfoInner(ctx, err, "failed to write first UDP payload")
			conn.Close()
			return
		}
	}
}

func handleInput(ctx context.Context, conn *connEntry, dest net.Destination, callback ResponseCallback, callClose func() error) {
	defer func() {
		conn.Close()
		if callClose != nil {
			callClose()
		}
	}()

	input := conn.link.Reader
	timer := conn.timer

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		mb, err := input.ReadMultiBuffer()
		if err != nil {
			if !goerrors.Is(err, io.EOF) {
				errors.LogInfoInner(ctx, err, "failed to handle UDP input")
			}
			return
		}
		timer.Update()
		for _, b := range mb {
			if b.UDP != nil {
				dest = *b.UDP
			}
			callback(ctx, &udp.Packet{
				Payload: b,
				Source:  dest,
			})
		}
	}
}

type dispatcherConn struct {
	dispatcher *Dispatcher
	cache      chan *udp.Packet
	done       *done.Instance
	ctx        context.Context
}

func DialDispatcher(ctx context.Context, dispatcher routing.Dispatcher) (net.PacketConn, error) {
	c := &dispatcherConn{
		cache: make(chan *udp.Packet, 16),
		done:  done.New(),
		ctx:   ctx,
	}

	d := &Dispatcher{
		dispatcher: dispatcher,
		callback:   c.callback,
		callClose:  c.Close,
	}
	c.dispatcher = d
	return c, nil
}

func (c *dispatcherConn) callback(ctx context.Context, packet *udp.Packet) {
	select {
	case <-c.done.Wait():
		packet.Payload.Release()
		return
	case c.cache <- packet:
	default:
		packet.Payload.Release()
		return
	}
}

func (c *dispatcherConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var packet *udp.Packet
s:
	select {
	case <-c.done.Wait():
		select {
		case packet = <-c.cache:
			break s
		default:
			return 0, nil, io.EOF
		}
	case packet = <-c.cache:
	}
	return copy(p, packet.Payload.Bytes()), &net.UDPAddr{
		IP:   packet.Source.Address.IP(),
		Port: int(packet.Source.Port),
	}, nil
}

func (c *dispatcherConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	buffer := buf.New()
	raw := buffer.Extend(buf.Size)
	n := copy(raw, p)
	buffer.Resize(0, int32(n))

	destination := net.DestinationFromAddr(addr)
	buffer.UDP = &destination
	c.dispatcher.Dispatch(c.ctx, destination, buffer)
	return n, nil
}

func (c *dispatcherConn) Close() error {
	return c.done.Close()
}

func (c *dispatcherConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   []byte{0, 0, 0, 0},
		Port: 0,
	}
}

func (c *dispatcherConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *dispatcherConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *dispatcherConn) SetWriteDeadline(t time.Time) error {
	return nil
}
