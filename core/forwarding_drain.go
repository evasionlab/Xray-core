package core

import (
	"context"
	stdtls "crypto/tls"
	"sort"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/internal/forwardingdrain"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ForwardingDrainConfig is a local, explicit construction boundary. It is not
// enrollment, durable admission closure, static-Core authorization or billing.
type ForwardingDrainConfig struct {
	InboundTags          []string
	MaxParents, MaxTasks uint32
}
type (
	PhysicalJoinResult = forwardingdrain.Result
	ForwardingDrain    struct {
		instance *Instance
		owner    *forwardingdrain.Owner
	}
)

var ErrForwardingGraphUnsupported = forwardingdrain.ErrUnsupported

// NewWithForwardingDrain supports only a complete, fixed builtin-dispatcher
// Trojan/TCP + simple-freedom graph. Ordinary constructors remain unchanged.
func NewWithForwardingDrain(ctx context.Context, config *Config, c ForwardingDrainConfig) (*Instance, *ForwardingDrain, error) {
	if ctx == nil || config == nil {
		return nil, nil, ErrForwardingGraphUnsupported
	}
	frozen := proto.Clone(config).(*Config)
	if err := validateDrainGraph(frozen, c); err != nil {
		return nil, nil, err
	}
	owner, err := forwardingdrain.New(append([]string(nil), c.InboundTags...), forwardingdrain.Limits{MaxParents: c.MaxParents, MaxTasks: c.MaxTasks})
	if err != nil {
		return nil, nil, err
	}
	server := &Instance{ctx: forwardingdrain.WithOwner(ctx, owner), forwardingDrain: owner, forwardingConfig: frozen}
	done, err := initInstanceWithConfig(frozen, server)
	if done {
		owner.Seal()
		server.Close()
		return nil, nil, err
	}
	server.forwardingInitialized.Store(true)
	return server, &ForwardingDrain{server, owner}, nil
}

// CloseAndJoin is volatile physical completion for this exact Instance only.
// Deadline/error yields zero result and leaves the instance terminally sealed.
// There is no counter census, restart proof, OS-success count or financial claim.
func (d *ForwardingDrain) CloseAndJoin(ctx context.Context) (PhysicalJoinResult, error) {
	if d == nil || d.instance == nil || d.instance.forwardingDrain != d.owner {
		return PhysicalJoinResult{}, forwardingdrain.ErrAuthority
	}
	return d.owner.Join(ctx)
}

// ValidateForwardingGraphMutation is used by managers with their constructor's
// captured instance context. A caller cannot replace that authority via ctx.
func ValidateForwardingGraphMutation(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	s := FromContext(ctx)
	if s != nil && s.forwardingDrain != nil && s.forwardingInitialized.Load() {
		return ErrForwardingGraphUnsupported
	}
	return nil
}

func ValidateForwardingInbound(ctx context.Context, c *InboundHandlerConfig) error {
	s := FromContext(ctx)
	if s == nil || s.forwardingDrain == nil {
		return nil
	}
	if e := s.forwardingDrain.CheckOpen(); e != nil {
		return e
	}
	for _, fixed := range s.forwardingConfig.Inbound {
		if proto.Equal(fixed, c) {
			return nil
		}
	}
	return ErrForwardingGraphUnsupported
}

func ValidateForwardingOutbound(ctx context.Context, c *OutboundHandlerConfig) error {
	s := FromContext(ctx)
	if s == nil || s.forwardingDrain == nil {
		return nil
	}
	if e := s.forwardingDrain.CheckOpen(); e != nil {
		return e
	}
	for _, fixed := range s.forwardingConfig.Outbound {
		if proto.Equal(fixed, c) {
			return nil
		}
	}
	return ErrForwardingGraphUnsupported
}

func typed(m *serial.TypedMessage, name string) (proto.Message, error) {
	if m == nil || m.Type != name || !knownMessage(m.ProtoReflect()) {
		return nil, ErrForwardingGraphUnsupported
	}
	v, e := m.GetInstance()
	if e != nil || !knownMessage(v.ProtoReflect()) {
		return nil, ErrForwardingGraphUnsupported
	}
	return v, nil
}

// Unknown fields are rejected recursively, including decoded typed wrappers.
// This validation is limited to this explicit graph, not the ordinary parser.
func knownMessage(m protoreflect.Message) bool { return knownMessageDepth(m, 0) }

func knownMessageDepth(m protoreflect.Message, depth int) bool {
	if depth > 64 || !m.IsValid() || len(m.GetUnknown()) != 0 {
		return false
	}
	if typed, ok := m.Interface().(*serial.TypedMessage); ok {
		v, e := typed.GetInstance()
		if e != nil {
			return false
		}
		return knownMessageDepth(v.ProtoReflect(), depth+1)
	}
	valid := true
	m.Range(func(f protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if f.IsMap() {
			if f.MapValue().Kind() == protoreflect.MessageKind {
				v.Map().Range(func(_ protoreflect.MapKey, x protoreflect.Value) bool {
					valid = knownMessageDepth(x.Message(), depth+1)
					return valid
				})
			}
		} else if f.IsList() && f.Kind() == protoreflect.MessageKind {
			for i := 0; i < v.List().Len(); i++ {
				if !knownMessageDepth(v.List().Get(i).Message(), depth+1) {
					valid = false
					break
				}
			}
		} else if f.Kind() == protoreflect.MessageKind {
			valid = knownMessageDepth(v.Message(), depth+1)
		}
		return valid
	})
	return valid
}

func bytesField(m protoreflect.Message, name protoreflect.Name) []byte {
	return m.Get(m.Descriptor().Fields().ByName(name)).Bytes()
}

func present(m proto.Message, name protoreflect.Name) bool {
	r := m.ProtoReflect()
	f := r.Descriptor().Fields().ByName(name)
	if f == nil {
		return false
	}
	if f.IsList() {
		return r.Get(f).List().Len() != 0
	}
	return r.Has(f)
}

func validateDrainGraph(c *Config, requested ForwardingDrainConfig) error {
	if !knownMessage(c.ProtoReflect()) || len(c.Extension) != 0 || len(c.Inbound) < 1 || len(c.Inbound) > 2 || len(c.Outbound) != 1 || len(requested.InboundTags) != len(c.Inbound) {
		return ErrForwardingGraphUnsupported
	}
	allowed := map[string]bool{"xray.app.dispatcher.Config": true, "xray.app.proxyman.InboundConfig": true, "xray.app.proxyman.OutboundConfig": true, "xray.app.policy.Config": true, "xray.app.stats.Config": true, "xray.app.log.Config": true}
	seen := map[string]bool{}
	for _, a := range c.App {
		if a == nil || !allowed[a.Type] || seen[a.Type] {
			return ErrForwardingGraphUnsupported
		}
		if _, e := typed(a, a.Type); e != nil {
			return e
		}
		seen[a.Type] = true
	}
	if !seen["xray.app.dispatcher.Config"] || !seen["xray.app.proxyman.InboundConfig"] || !seen["xray.app.proxyman.OutboundConfig"] {
		return ErrForwardingGraphUnsupported
	}
	tags := make([]string, 0, len(c.Inbound))
	for _, in := range c.Inbound {
		if in == nil || in.Tag == "" || len(in.ProtoReflect().GetUnknown()) != 0 {
			return ErrForwardingGraphUnsupported
		}
		tags = append(tags, in.Tag)
		p, e := typed(in.ProxySettings, "xray.proxy.trojan.ServerConfig")
		if e != nil || present(p, "fallbacks") {
			return ErrForwardingGraphUnsupported
		}
		raw, e := typed(in.ReceiverSettings, "xray.app.proxyman.ReceiverConfig")
		if e != nil {
			return e
		}
		r, ok := raw.(*proxyman.ReceiverConfig)
		if !ok || r.PortList == nil || len(r.PortList.Range) != 1 || r.PortList.Range[0] == nil || r.PortList.Range[0].From < 1 || r.PortList.Range[0].From > 65535 || r.PortList.Range[0].From != r.PortList.Range[0].To || r.ReceiveOriginalDestination || r.SniffingSettings != nil || r.Listen == nil || r.Listen.GetDomain() != "" || (len(r.Listen.GetIp()) != 4 && len(r.Listen.GetIp()) != 16) {
			return ErrForwardingGraphUnsupported
		}
		stream := r.StreamSettings
		if stream == nil || stream.ProtocolName != "tcp" || stream.SocketSettings != nil || len(stream.Tcpmasks) != 0 || len(stream.Udpmasks) != 0 || stream.QuicParams != nil || stream.Address != nil || stream.Port != 0 {
			return ErrForwardingGraphUnsupported
		}
		if stream.SecurityType != "xray.transport.internet.tls.Config" || len(stream.SecuritySettings) != 1 || len(stream.TransportSettings) > 1 {
			return ErrForwardingGraphUnsupported
		}
		v, e := typed(stream.SecuritySettings[0], "xray.transport.internet.tls.Config")
		if e != nil {
			return e
		}
		for _, field := range []protoreflect.Name{"fingerprint", "master_key_log", "ech_server_keys", "ech_config_list", "ech_socket_settings", "verify_peer_cert_by_name", "pinned_peer_cert_sha256"} {
			if present(v, field) {
				return ErrForwardingGraphUnsupported
			}
		}
		certs := v.ProtoReflect().Get(v.ProtoReflect().Descriptor().Fields().ByName("certificate")).List()
		if certs.Len() != 1 {
			return ErrForwardingGraphUnsupported
		}
		cert := certs.Get(0).Message()
		if !cert.Get(cert.Descriptor().Fields().ByName("One_time_loading")).Bool() {
			return ErrForwardingGraphUnsupported
		}
		for _, field := range []protoreflect.Name{"usage", "ocsp_stapling", "certificate_path", "key_path", "build_chain"} {
			f := cert.Descriptor().Fields().ByName(field)
			if cert.Has(f) {
				return ErrForwardingGraphUnsupported
			}
		}
		if _, e := stdtls.X509KeyPair(bytesField(cert, "certificate"), bytesField(cert, "key")); e != nil {
			return ErrForwardingGraphUnsupported
		}
		for _, setting := range stream.TransportSettings {
			if setting == nil || setting.ProtocolName != "tcp" {
				return ErrForwardingGraphUnsupported
			}
			v, e := typed(setting.Settings, "xray.transport.internet.tcp.Config")
			if e != nil || present(v, "header_settings") || present(v, "accept_proxy_protocol") {
				return ErrForwardingGraphUnsupported
			}
		}

	}
	want := append([]string(nil), requested.InboundTags...)
	sort.Strings(want)
	sort.Strings(tags)
	for i := range tags {
		if tags[i] != want[i] || (i > 0 && tags[i-1] == tags[i]) {
			return ErrForwardingGraphUnsupported
		}
	}
	out := c.Outbound[0]
	if out == nil || out.Tag == "" || len(out.ProtoReflect().GetUnknown()) != 0 {
		return ErrForwardingGraphUnsupported
	}
	p, e := typed(out.ProxySettings, "xray.proxy.freedom.Config")
	if e != nil {
		return e
	}
	for _, field := range []protoreflect.Name{"destination_override", "fragment", "proxy_protocol", "noises"} {
		if present(p, field) {
			return ErrForwardingGraphUnsupported
		}
	}
	if f := p.ProtoReflect().Descriptor().Fields().ByName("domain_strategy"); p.ProtoReflect().Get(f).Enum() != 0 {
		return ErrForwardingGraphUnsupported
	}
	if out.SenderSettings != nil {
		raw, e := typed(out.SenderSettings, "xray.app.proxyman.SenderConfig")
		if e != nil {
			return e
		}
		s := raw.(*proxyman.SenderConfig)
		if s.ProxySettings != nil || s.MultiplexSettings != nil || s.TargetStrategy != 0 || s.StreamSettings != nil || s.ViaCidr != "" || (s.Via != nil && (s.Via.GetDomain() != "" || (len(s.Via.GetIp()) != 4 && len(s.Via.GetIp()) != 16))) {
			return ErrForwardingGraphUnsupported
		}
	}
	return nil
}
