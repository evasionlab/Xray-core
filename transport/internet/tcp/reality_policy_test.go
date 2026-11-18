package tcp_test

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tcp"
)

type admissionPolicy struct{ reads atomic.Int32 }

func (*admissionPolicy) Type() interface{}        { return policy.ManagerType() }
func (*admissionPolicy) Start() error             { return nil }
func (*admissionPolicy) Close() error             { return nil }
func (*admissionPolicy) ForSystem() policy.System { return policy.System{} }
func (p *admissionPolicy) ForLevel(level uint32) policy.Session {
	if level != 0 {
		panic("pre-auth policy must use level zero")
	}
	p.reads.Add(1)
	session := policy.SessionDefault()
	session.Timeouts.Handshake = 100 * time.Millisecond
	return session
}

func TestREALITYListenerUsesConfiguredHandshakePolicy(t *testing.T) {
	// Keep Unix socket paths below platform limits, independent of test temp roots.
	dir, err := os.MkdirTemp("/tmp", "reality-policy-")
	common.Must(err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "inbound.sock")
	manager := new(admissionPolicy)
	instance := new(core.Instance)
	common.Must(instance.AddFeature(manager))
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	var admitted atomic.Int32
	listener, err := tcp.ListenTCP(ctx, xnet.DomainAddress(path), 0, &internet.MemoryStreamConfig{
		ProtocolSettings: &tcp.Config{},
		SecuritySettings: &reality.Config{Type: "tcp", Dest: "127.0.0.1:1"},
	}, func(connection stat.Connection) { admitted.Add(1); connection.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = client.Read(make([]byte, 1))
	if err != io.EOF {
		t.Fatalf("silent connection was not closed by configured policy: %v", err)
	}
	if manager.reads.Load() != 1 {
		t.Fatalf("listener did not read its level-zero policy: %d", manager.reads.Load())
	}
	if admitted.Load() != 0 {
		t.Fatal("admitted silent connection before authentication")
	}
}
