package core_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/internal/forwardingdrain"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	xudp "github.com/xtls/xray-core/transport/internet/udp"
	"github.com/xtls/xray-core/transport/pipe"
	"google.golang.org/protobuf/proto"
)

func drainCertificate(t *testing.T) ([]byte, []byte, *x509.CertPool) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	k, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("fixture cert")
	}
	return cert, private, roots
}

func drainConfig(t *testing.T) (*core.Config, *x509.CertPool, []string) {
	t.Helper()
	cert, key, roots := drainCertificate(t)
	cfg := &core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})}, Outbound: []*core.OutboundHandlerConfig{{Tag: "direct", ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow, Networks: []xnet.Network{xnet.Network_TCP, xnet.Network_UDP}, Ip: []*geodata.IPRule{{Value: &geodata.IPRule_Custom{Custom: &geodata.CIDRRule{Cidr: &geodata.CIDR{Ip: []byte{127, 0, 0, 1}, Prefix: 32}}}}}}}})}}}
	addresses := []string{}
	for _, tag := range []string{"first", "second"} {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		port := uint32(l.Addr().(*net.TCPAddr).Port)
		addresses = append(addresses, l.Addr().String())
		l.Close()
		cfg.Inbound = append(cfg.Inbound, &core.InboundHandlerConfig{Tag: tag, ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: xnet.NewIPOrDomain(xnet.LocalHostIP), PortList: &xnet.PortList{Range: []*xnet.PortRange{{From: port, To: port}}}, StreamSettings: &internet.StreamConfig{ProtocolName: "tcp", SecurityType: "xray.transport.internet.tls.Config", SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(&xtls.Config{Certificate: []*xtls.Certificate{{Certificate: cert, Key: key, OneTimeLoading: true}}})}}}), ProxySettings: serial.ToTypedMessage(&trojan.ServerConfig{Users: []*protocol.User{{Email: tag, Account: serial.ToTypedMessage(&trojan.Account{Password: "drain-private-qa"})}}})})
	}
	return cfg, roots, addresses
}

func drainOptions() core.ForwardingDrainConfig {
	return core.ForwardingDrainConfig{InboundTags: []string{"first", "second"}, MaxParents: 16, MaxTasks: 128}
}

func echoEndpoint(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var conns []net.Conn
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			workers.Add(1)
			go func() { defer workers.Done(); defer c.Close(); io.Copy(c, c) }()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return l.Addr().String()
}

func drainDial(t *testing.T, address string, roots *x509.CertPool) net.Conn {
	t.Helper()
	raw, e := net.DialTimeout("tcp", address, 3*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	c := stdtls.Client(raw, &stdtls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: stdtls.VersionTLS12})
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if e := c.Handshake(); e != nil {
		raw.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func drainTCP(t *testing.T, address, target string, roots *x509.CertPool) net.Conn {
	t.Helper()
	c := drainDial(t, address, roots)
	dest, e := xnet.ParseDestination("tcp:" + target)
	if e != nil {
		t.Fatal(e)
	}
	a, e := (&trojan.Account{Password: "drain-private-qa"}).AsAccount()
	if e != nil {
		t.Fatal(e)
	}
	w := &trojan.ConnWriter{Writer: c, Target: dest, Account: a.(*trojan.MemoryAccount)}
	if _, e := w.Write([]byte("payload")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 7)
	if _, e := io.ReadFull(c, b); e != nil || string(b) != "payload" {
		t.Fatalf("real Trojan forwarding: %q %v", b, e)
	}
	c.SetDeadline(time.Time{})
	return c
}

func drainUDP(t *testing.T, address string, roots *x509.CertPool) net.Conn {
	t.Helper()
	u, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 64)
		for {
			n, a, e := u.ReadFromUDP(b)
			if e != nil {
				return
			}
			u.WriteToUDP(b[:n], a)
		}
	}()
	t.Cleanup(func() { u.Close(); <-done })
	c := drainDial(t, address, roots)
	dest := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(u.LocalAddr().(*net.UDPAddr).Port))
	a, e := (&trojan.Account{Password: "drain-private-qa"}).AsAccount()
	if e != nil {
		t.Fatal(e)
	}
	header := &trojan.ConnWriter{Writer: c, Target: dest, Account: a.(*trojan.MemoryAccount)}
	packet := append([]byte{1, 127, 0, 0, 1, byte(dest.Port >> 8), byte(dest.Port), 0, 7, '\r', '\n'}, []byte("udp-qa!")...)
	if _, e := header.Write(packet); e != nil {
		t.Fatal(e)
	}
	r := &trojan.PacketReader{Reader: c}
	mb, e := r.ReadMultiBuffer()
	if e != nil {
		t.Fatal(e)
	}
	if len(mb) != 1 || string(mb[0].Bytes()) != "udp-qa!" {
		t.Fatal("genuine UDP-over-TCP payload mismatch")
	}
	for _, b := range mb {
		b.Release()
	}
	c.SetDeadline(time.Time{})
	return c
}

func TestForwardingDrainGenuineTwoBindingTCPAndUDP(t *testing.T) {
	cfg, roots, addresses := drainConfig(t)
	server, drain, e := core.NewWithForwardingDrain(context.Background(), cfg, drainOptions())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { server.Close() })
	if e := server.Start(); e != nil {
		t.Fatal(e)
	}
	// Mutating caller-owned config must not extend the instance's frozen graph.
	cfg.Inbound[0].Tag = "foreign"
	endpoint := echoEndpoint(t)
	clients := []net.Conn{drainTCP(t, addresses[0], endpoint, roots), drainTCP(t, addresses[1], endpoint, roots), drainUDP(t, addresses[0], roots)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, e := drain.CloseAndJoin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if result.PhysicalJoin != "completed" || result.FinalAccounting != "not_proven" || result.CapturedParents < 3 || result.CapturedTasks < 6 || result.CapturedParents != result.JoinedParents || result.CapturedTasks != result.JoinedTasks {
		t.Fatalf("wrong physical census: %+v", result)
	}
	for _, c := range clients {
		c.SetReadDeadline(time.Now().Add(time.Second))
		b := make([]byte, 1)
		if _, e := c.Read(b); e == nil {
			t.Fatal("native forwarding socket remained open")
		} else if x, ok := e.(net.Error); ok && x.Timeout() {
			t.Fatal("join claimed completion without native socket closure")
		}
	}
	if e := server.Start(); e == nil {
		t.Fatal("sealed instance restarted")
	}
	t.Logf("actual Trojan TCP both bindings + UDP-over-TCP joined: parents=%d tasks=%d; final accounting not proven", result.JoinedParents, result.JoinedTasks)
}

func TestForwardingDrainRejectsUnsupportedBeforeEffects(t *testing.T) {
	base, _, addresses := drainConfig(t)
	cases := map[string]func(*core.Config){
		"extension": func(c *core.Config) {
			c.Extension = []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{})}
		},
		"nil_range": func(c *core.Config) {
			v, _ := c.Inbound[0].ReceiverSettings.GetInstance()
			r := v.(*proxyman.ReceiverConfig)
			r.PortList.Range = []*xnet.PortRange{nil}
			c.Inbound[0].ReceiverSettings = serial.ToTypedMessage(r)
		},
		"fallback": func(c *core.Config) {
			v, _ := c.Inbound[0].ProxySettings.GetInstance()
			r := v.(*trojan.ServerConfig)
			r.Fallbacks = []*trojan.Fallback{{Dest: "127.0.0.1:1"}}
			c.Inbound[0].ProxySettings = serial.ToTypedMessage(r)
		},
		"plaintext": func(c *core.Config) {
			v, _ := c.Inbound[0].ReceiverSettings.GetInstance()
			r := v.(*proxyman.ReceiverConfig)
			r.StreamSettings.SecurityType = ""
			r.StreamSettings.SecuritySettings = nil
			c.Inbound[0].ReceiverSettings = serial.ToTypedMessage(r)
		},
		"nil_transport": func(c *core.Config) {
			v, _ := c.Inbound[0].ReceiverSettings.GetInstance()
			r := v.(*proxyman.ReceiverConfig)
			r.StreamSettings.TransportSettings = []*internet.TransportConfig{nil}
			c.Inbound[0].ReceiverSettings = serial.ToTypedMessage(r)
		},
		"nested_unknown": func(c *core.Config) {
			v, _ := c.Inbound[0].ProxySettings.GetInstance()
			r := v.(*trojan.ServerConfig)
			u, _ := r.Users[0].Account.GetInstance()
			u.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
			r.Users[0].Account = serial.ToTypedMessage(u)
			c.Inbound[0].ProxySettings = serial.ToTypedMessage(r)
		},
		"reload_certificate": func(c *core.Config) {
			v, _ := c.Inbound[0].ReceiverSettings.GetInstance()
			r := v.(*proxyman.ReceiverConfig)
			tls, _ := r.StreamSettings.SecuritySettings[0].GetInstance()
			tls.(*xtls.Config).Certificate[0].OneTimeLoading = false
			r.StreamSettings.SecuritySettings[0] = serial.ToTypedMessage(tls)
			c.Inbound[0].ReceiverSettings = serial.ToTypedMessage(r)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := proto.Clone(base).(*core.Config)
			change(c)
			server, drain, e := core.NewWithForwardingDrain(context.Background(), c, drainOptions())
			if !errors.Is(e, core.ErrForwardingGraphUnsupported) || server != nil || drain != nil {
				t.Fatalf("unsupported graph admitted %v", e)
			}
			for _, a := range addresses {
				l, e := net.Listen("tcp", a)
				if e != nil {
					t.Fatal("rejected constructor had listener effect")
				}
				l.Close()
			}
		})
	}
}

type rejectedFeature struct{ starts int }

func (f *rejectedFeature) Start() error { f.starts++; return nil }
func (*rejectedFeature) Close() error   { return nil }
func (*rejectedFeature) Type() any      { return (*rejectedFeature)(nil) }

type rejectedInbound struct{ rejectedFeature }

func (*rejectedInbound) Tag() string                            { return "foreign" }
func (*rejectedInbound) ReceiverSettings() *serial.TypedMessage { return nil }
func (*rejectedInbound) ProxySettings() *serial.TypedMessage    { return nil }

type rejectedOutbound struct{ rejectedFeature }

func (*rejectedOutbound) SenderSettings() *serial.TypedMessage      { return nil }
func (*rejectedOutbound) ProxySettings() *serial.TypedMessage       { return nil }
func (*rejectedOutbound) Tag() string                               { return "foreign" }
func (*rejectedOutbound) Dispatch(context.Context, *transport.Link) {}
func TestForwardingDrainFrozenFeaturesAndManagers(t *testing.T) {
	cfg, _, _ := drainConfig(t)
	s, d, e := core.NewWithForwardingDrain(context.Background(), cfg, drainOptions())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	for _, start := range []bool{false, true} {
		if start {
			if e := s.Start(); e != nil {
				t.Fatal(e)
			}
		}
		feature := &rejectedFeature{}
		if e := s.AddFeature(feature); e == nil || feature.starts != 0 {
			t.Fatal("late feature effects")
		}
		im := s.GetFeature(inbound.ManagerType()).(inbound.Manager)
		ih := &rejectedInbound{}
		if e := im.AddHandler(context.Background(), ih); e == nil || ih.starts != 0 {
			t.Fatal("foreign inbound admitted")
		}
		if e := im.RemoveHandler(context.Background(), "first"); e == nil {
			t.Fatal("frozen inbound removed")
		}
		om := s.GetFeature(outbound.ManagerType()).(outbound.Manager)
		oh := &rejectedOutbound{}
		if e := om.AddHandler(context.Background(), oh); e == nil || oh.starts != 0 {
			t.Fatal("foreign outbound admitted")
		}
		if e := om.RemoveHandler(context.Background(), "direct"); e == nil {
			t.Fatal("frozen outbound removed")
		}
	}
	if _, e := d.CloseAndJoin(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := s.AddFeature(&rejectedFeature{}); e == nil {
		t.Fatal("closed graph adopted feature")
	}
}

func TestForwardingDrainActualUDPCallbackHeldUntilJoin(t *testing.T) {
	cfg, _, _ := drainConfig(t)
	s, d, e := core.NewWithForwardingDrain(context.Background(), cfg, drainOptions())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := forwardingdrain.ListenerContext(core.ForwardingDrainTestContext(s), "first")
	parent, e := forwardingdrain.Root(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	socket, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		b := make([]byte, 32)
		n, a, e := socket.ReadFromUDP(b)
		if e == nil {
			socket.WriteToUDP(b[:n], a)
		}
	}()
	defer func() { socket.Close(); <-peerDone }()
	entered, release, callbackDone, finished := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	actual := s.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	udpDispatcher := xudp.NewDispatcher(actual, func(_ context.Context, p *protocoludp.Packet) {
		defer p.Payload.Release()
		defer close(callbackDone)
		if string(p.Payload.Bytes()) != "udp-owned" {
			t.Error("actual UDP response mismatch")
		}
		close(entered)
		<-release
	})
	payload := buf.New()
	payload.WriteString("udp-owned")
	destination := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(socket.LocalAddr().(*net.UDPAddr).Port))
	udpDispatcher.Dispatch(parent.Context(ctx), destination, payload)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("actual Core UDP callback not reached")
	}
	go func() { <-parent.Context(ctx).Done(); udpDispatcher.CloseAndJoin(); parent.Done(); close(finished) }()
	timeout, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	r, e := d.CloseAndJoin(timeout)
	if !errors.Is(e, context.DeadlineExceeded) || r != (core.PhysicalJoinResult{}) {
		t.Fatalf("held actual callback claimed joined: %+v %v", r, e)
	}
	select {
	case <-finished:
		t.Fatal("parent done before native callback returned")
	default:
	}
	once.Do(func() { close(release) })
	select {
	case <-callbackDone:
	case <-time.After(3 * time.Second):
		t.Fatal("callback cleanup not returned")
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("UDP handleInput/parent not joined")
	}
	r, e = d.CloseAndJoin(context.Background())
	if e != nil || r.JoinedParents != 1 || r.JoinedTasks < 3 {
		t.Fatalf("actual UDP join result %+v %v", r, e)
	}
}

func TestForwardingDrainRejectsUnownedAndForeignDispatch(t *testing.T) {
	cfg, _, _ := drainConfig(t)
	s, d, e := core.NewWithForwardingDrain(context.Background(), cfg, drainOptions())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	defer d.CloseAndJoin(context.Background())
	actual := s.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	foreign, e := forwardingdrain.New([]string{"first"}, forwardingdrain.Limits{MaxParents: 8, MaxTasks: 64})
	if e != nil {
		t.Fatal(e)
	}
	foreignCtx := forwardingdrain.ListenerContext(forwardingdrain.WithOwner(context.Background(), foreign), "first")
	token, e := forwardingdrain.Root(foreignCtx, true)
	if e != nil {
		t.Fatal(e)
	}
	defer token.Done()
	target := xnet.TCPDestination(xnet.LocalHostIP, 1)
	for _, ctx := range []context.Context{context.Background(), core.ForwardingDrainTestContext(s), token.Context(foreignCtx)} {
		if link, e := actual.Dispatch(ctx, target); e == nil || link != nil {
			t.Fatal("unowned dispatch effects")
		}
		if e := actual.DispatchLink(ctx, target, &transport.Link{}); e == nil {
			t.Fatal("unowned DispatchLink effects")
		}
	}
}

type nativeHeldRead struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
}

func (c *nativeHeldRead) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if n > 0 {
		c.once.Do(func() { close(c.entered) })
		<-c.release
	}
	return n, e
}

type nativeHeldDialer struct{ entered, release chan struct{} }

func (d *nativeHeldDialer) Dial(ctx context.Context, target xnet.Destination) (stat.Connection, error) {
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp", target.NetAddr())
	if e != nil {
		return nil, e
	}
	return &nativeHeldRead{Conn: c, entered: d.entered, release: d.release}, nil
}
func (*nativeHeldDialer) DestIpAddress() xnet.IP                                { return nil }
func (*nativeHeldDialer) SetOutboundGateway(context.Context, *session.Outbound) {}
func TestForwardingDrainNativeFreedomResponseSiblingHeld(t *testing.T) {
	cfg, _, _ := drainConfig(t)
	s, d, e := core.NewWithForwardingDrain(context.Background(), cfg, drainOptions())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	raw, e := cfg.Outbound[0].ProxySettings.GetInstance()
	if e != nil {
		t.Fatal(e)
	}
	handler := new(freedom.Handler)
	if e := handler.Init(raw.(*freedom.Config), s.GetFeature(policy.ManagerType()).(policy.Manager)); e != nil {
		t.Fatal(e)
	}
	ctx := forwardingdrain.ListenerContext(core.ForwardingDrainTestContext(s), "first")
	parent, e := forwardingdrain.Root(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	target, e := xnet.ParseDestination("tcp:" + echoEndpoint(t))
	if e != nil {
		t.Fatal(e)
	}
	ctx = session.ContextWithOutbounds(parent.Context(ctx), []*session.Outbound{{Target: target, OriginalTarget: target}})
	input, write := pipe.New(pipe.WithSizeLimit(1024))
	read, output := pipe.New(pipe.WithSizeLimit(1024))
	defer read.Interrupt()
	defer write.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	done := make(chan struct{})
	go func() {
		handler.Process(ctx, &transport.Link{Reader: input, Writer: output}, &nativeHeldDialer{entered: entered, release: release})
		parent.Done()
		close(done)
	}()
	b := buf.New()
	b.WriteString("real-response")
	if e := write.WriteMultiBuffer(buf.MultiBuffer{b}); e != nil {
		t.Fatal(e)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("actual native response copy not reached")
	}
	// Actual upstream EOF lets the request sibling finish. The response sibling
	// has performed a real TCP read but cannot return/clean up until released.
	write.Close()
	timeout, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	r, e := d.CloseAndJoin(timeout)
	if !errors.Is(e, context.DeadlineExceeded) || r != (core.PhysicalJoinResult{}) {
		t.Fatalf("held native sibling claimed completion %+v %v", r, e)
	}
	select {
	case <-done:
		t.Fatal("Process returned before native response copy completion")
	default:
	}
	once.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("native siblings failed to join")
	}
	if r, e := d.CloseAndJoin(context.Background()); e != nil || r.JoinedParents != 1 || r.JoinedTasks < 1 {
		t.Fatalf("native sibling join %+v %v", r, e)
	}
}

func TestForwardingDrainNativeFreedomRequestSiblingHeld(t *testing.T) {
	cfg, _, _ := drainConfig(t)
	s, d, e := core.NewWithForwardingDrain(context.Background(), cfg, drainOptions())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	raw, e := cfg.Outbound[0].ProxySettings.GetInstance()
	if e != nil {
		t.Fatal(e)
	}
	handler := new(freedom.Handler)
	if e := handler.Init(raw.(*freedom.Config), s.GetFeature(policy.ManagerType()).(policy.Manager)); e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			accepted <- c
		} else {
			accepted <- nil
		}
	}()
	sender, e := net.Dial("tcp", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	receiver := <-accepted
	if receiver == nil {
		t.Fatal("native incoming accept")
	}
	defer receiver.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	held := &nativeHeldRead{Conn: receiver, entered: entered, release: release}
	ctx := forwardingdrain.ListenerContext(core.ForwardingDrainTestContext(s), "first")
	parent, e := forwardingdrain.Root(ctx, true, receiver)
	if e != nil {
		t.Fatal(e)
	}
	target, e := xnet.ParseDestination("tcp:" + echoEndpoint(t))
	if e != nil {
		t.Fatal(e)
	}
	ctx = session.ContextWithOutbounds(parent.Context(ctx), []*session.Outbound{{Target: target, OriginalTarget: target}})
	done := make(chan struct{})
	go func() {
		handler.Process(ctx, &transport.Link{Reader: buf.NewReader(held), Writer: buf.Discard}, &nativeHeldDialer{entered: make(chan struct{}), release: release})
		parent.Done()
		close(done)
	}()
	if _, e := sender.Write([]byte("held-native-request")); e != nil {
		t.Fatal(e)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("native request copy not reached")
	}
	timeout, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	r, e := d.CloseAndJoin(timeout)
	if !errors.Is(e, context.DeadlineExceeded) || r != (core.PhysicalJoinResult{}) {
		t.Fatalf("held request claimed completion %+v %v", r, e)
	}
	select {
	case <-done:
		t.Fatal("Process ended while request copy held")
	default:
	}
	once.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("native request copy did not join")
	}
	if r, e := d.CloseAndJoin(context.Background()); e != nil || r.JoinedParents != 1 || r.JoinedTasks < 1 {
		t.Fatalf("native request join %+v %v", r, e)
	}
}

func TestForwardingDrainDirectHandlerRequiresItsAdmittedDispatch(t *testing.T) {
	cfg, _, _ := drainConfig(t)
	s, d, e := core.NewWithForwardingDrain(context.Background(), cfg, drainOptions())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	defer d.CloseAndJoin(context.Background())
	h := s.GetFeature(outbound.ManagerType()).(outbound.Manager).GetDefaultHandler()
	dialer := h.(internet.Dialer)
	ownCtx := forwardingdrain.ListenerContext(core.ForwardingDrainTestContext(s), "first")
	own, e := forwardingdrain.Root(ownCtx, true)
	if e != nil {
		t.Fatal(e)
	}
	defer own.Done()
	foreign, e := forwardingdrain.New([]string{"first"}, forwardingdrain.Limits{MaxParents: 8, MaxTasks: 64})
	if e != nil {
		t.Fatal(e)
	}
	foreignCtx := forwardingdrain.ListenerContext(forwardingdrain.WithOwner(context.Background(), foreign), "first")
	other, e := forwardingdrain.Root(foreignCtx, true)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Done()
	target := xnet.TCPDestination(xnet.LocalHostIP, 1)
	for _, ctx := range []context.Context{context.Background(), core.ForwardingDrainTestContext(s), other.Context(foreignCtx)} {
		reader, write := pipe.New(pipe.WithSizeLimit(64))
		defer write.Close()
		h.Dispatch(ctx, &transport.Link{Reader: reader, Writer: buf.Discard})
		if _, e := reader.ReadMultiBuffer(); e == nil {
			t.Fatal("rejected direct dispatch did not clean supplied link")
		}
		if conn, e := dialer.Dial(ctx, target); e == nil || conn != nil {
			t.Fatal("unowned direct native dial")
		}
	}
	// Even a current same-owner parent is not the handler's admitted Dispatch.
	if conn, e := dialer.Dial(own.Context(ownCtx), target); e == nil || conn != nil {
		t.Fatal("parent context impersonated native handler Dispatch")
	}
}
