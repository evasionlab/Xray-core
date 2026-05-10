package session

import (
	gonet "net"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestOutboundEgressSourceFromAddr(t *testing.T) {
	ob := &Outbound{}
	ob.SetEgressSourceFromAddr(&gonet.TCPAddr{
		IP:   gonet.ParseIP("198.51.100.10"),
		Port: 47376,
	})

	source := ob.EgressSourceSnapshot()
	if !source.IsValid() {
		t.Fatal("expected egress source to be captured")
	}
	if got := source.Address.IP().String(); got != "198.51.100.10" {
		t.Fatalf("unexpected egress source ip: %s", got)
	}
	if source.Port != net.Port(47376) {
		t.Fatalf("unexpected egress source port: %d", source.Port)
	}
}

func TestSetOutboundEgressSourcePropagatesToAllOutbounds(t *testing.T) {
	first := &Outbound{}
	second := &Outbound{}
	source := net.UDPDestination(net.IPAddress(gonet.ParseIP("203.0.113.20")), 35788)

	SetOutboundEgressSource([]*Outbound{first, nil, second}, source)

	for _, ob := range []*Outbound{first, second} {
		got := ob.EgressSourceSnapshot()
		if got.Address.IP().String() != "203.0.113.20" || got.Port != net.Port(35788) {
			t.Fatalf("unexpected propagated egress source: %s", got.String())
		}
	}
}
