package dispatcher

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
)

func TestSnifferBittorrentFragments(t *testing.T) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	s := NewSniffer(ctx)
	header := []byte("\x13BitTorrent protocol")
	for _, n := range []int{1, 10, 15} {
		if _, err := s.Sniff(ctx, header[:n], net.Network_TCP); err != protocol.ErrProtoNeedMoreData {
			t.Fatalf("fragment %d: %v", n, err)
		}
	}
	result, err := s.Sniff(ctx, header, net.Network_TCP)
	if err != nil || result.Protocol() != "bittorrent" {
		t.Fatalf("complete prefix: %v", err)
	}
}

func TestSnifferDHTRegistration(t *testing.T) {
	ctx := context.WithValue(context.Background(), core.XrayKey(1), &core.Instance{})
	b := []byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")
	result, err := NewSniffer(ctx).Sniff(ctx, b, net.Network_UDP)
	if err != nil || result.Protocol() != "bittorrent" {
		t.Fatalf("DHT not registered: %v", err)
	}
	if result, err := NewSniffer(ctx).Sniff(ctx, b, net.Network_TCP); err == nil || result != nil {
		t.Fatal("DHT UDP detector matched TCP")
	}
}
