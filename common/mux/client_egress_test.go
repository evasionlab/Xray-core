package mux

import (
	gonet "net"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestClientWorkerSetsPendingLogicalOutboundEgressSource(t *testing.T) {
	worker := &ClientWorker{}
	logical := &session.Outbound{}

	worker.attachEgressSource([]*session.Outbound{logical})
	if logical.EgressSourceSnapshot().IsValid() {
		t.Fatal("logical outbound should not have egress source before worker captures it")
	}

	worker.setEgressSource(net.TCPDestination(net.IPAddress(gonet.ParseIP("198.51.100.30")), 45678))

	source := logical.EgressSourceSnapshot()
	if source.Address.IP().String() != "198.51.100.30" || source.Port != net.Port(45678) {
		t.Fatalf("unexpected logical egress source: %s", source.String())
	}
}

func TestClientWorkerSetsAlreadyKnownEgressSource(t *testing.T) {
	worker := &ClientWorker{}
	worker.setEgressSource(net.TCPDestination(net.IPAddress(gonet.ParseIP("203.0.113.40")), 35788))

	logical := &session.Outbound{}
	worker.attachEgressSource([]*session.Outbound{logical})

	source := logical.EgressSourceSnapshot()
	if source.Address.IP().String() != "203.0.113.40" || source.Port != net.Port(35788) {
		t.Fatalf("unexpected logical egress source: %s", source.String())
	}
}
