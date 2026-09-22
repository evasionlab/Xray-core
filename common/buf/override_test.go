package buf_test

import (
	"errors"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

type overrideEndpoint struct {
	data        buf.MultiBuffer
	closeErr    error
	closed      int
	interrupted int
	onClose     func()
	onInterrupt func()
}

func (e *overrideEndpoint) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return e.data, nil
}

func (e *overrideEndpoint) WriteMultiBuffer(data buf.MultiBuffer) error {
	e.data = data
	return nil
}

func (e *overrideEndpoint) Close() error {
	e.closed++
	if e.onClose != nil {
		e.onClose()
	}
	return e.closeErr
}

func (e *overrideEndpoint) Interrupt() {
	e.interrupted++
	if e.onInterrupt != nil {
		e.onInterrupt()
	}
}

func TestEndpointOverrideForwardsLifecycle(t *testing.T) {
	for _, reader := range []bool{true, false} {
		name := "writer"
		if reader {
			name = "reader"
		}
		t.Run(name, func(t *testing.T) {
			wantErr := errors.New("underlying close failure")
			endpoint := &overrideEndpoint{closeErr: wantErr}
			var wrapped any = &buf.EndpointOverrideWriter{Writer: endpoint}
			if reader {
				wrapped = &buf.EndpointOverrideReader{Reader: endpoint}
			}
			if err := common.Close(wrapped); !errors.Is(err, wantErr) {
				t.Fatalf("Close error=%v, want underlying error", err)
			}
			if endpoint.closed != 1 || endpoint.interrupted != 0 {
				t.Fatalf("Close calls=%d, Interrupt calls=%d", endpoint.closed, endpoint.interrupted)
			}
			if err := common.Interrupt(wrapped); err != nil {
				t.Fatal(err)
			}
			if endpoint.closed != 1 || endpoint.interrupted != 1 {
				t.Fatalf("Close calls=%d, Interrupt calls=%d", endpoint.closed, endpoint.interrupted)
			}
		})
	}
}

// Outbound Handler tears down a completed link by closing its writer and
// interrupting its reader. Address remapping must preserve both callbacks.
func TestEndpointOverridePreservesBothDirectionCompletion(t *testing.T) {
	var readDone, writeDone bool
	reader := &buf.EndpointOverrideReader{Reader: &overrideEndpoint{onInterrupt: func() { readDone = true }}}
	writer := &buf.EndpointOverrideWriter{Writer: &overrideEndpoint{onClose: func() { writeDone = true }}}
	if err := common.Close(writer); err != nil {
		t.Fatal(err)
	}
	if !writeDone || readDone {
		t.Fatal("writer half-close did not preserve the active reader")
	}
	if err := common.Interrupt(reader); err != nil {
		t.Fatal(err)
	}
	if !readDone || !writeDone {
		t.Fatal("completed outbound lost an underlying lifecycle callback")
	}
}

func TestEndpointOverridePreservesPayloadAndUnmatchedAddresses(t *testing.T) {
	original := net.DomainAddress("origin.example")
	resolved := net.IPAddress([]byte{192, 0, 2, 1})
	other := net.IPAddress([]byte{192, 0, 2, 2})
	for _, reader := range []bool{true, false} {
		name := "writer"
		from, to := resolved, original
		if reader {
			name, from, to = "reader", original, resolved
		}
		t.Run(name, func(t *testing.T) {
			data := buf.MultiBuffer{buf.FromBytes([]byte("matched payload")), buf.FromBytes([]byte("other payload")), buf.FromBytes([]byte("plain payload"))}
			defer buf.ReleaseMulti(data)
			matched := net.UDPDestination(from, 443)
			unmatched := net.UDPDestination(other, 53)
			data[0].UDP, data[1].UDP = &matched, &unmatched
			endpoint := &overrideEndpoint{data: data}
			if reader {
				wrapped := &buf.EndpointOverrideReader{Reader: endpoint, Dest: resolved, OriginalDest: original}
				got, err := wrapped.ReadMultiBuffer()
				if err != nil || len(got) != len(data) || got[0] != data[0] {
					t.Fatalf("read changed buffer ownership: %v", err)
				}
			} else {
				wrapped := &buf.EndpointOverrideWriter{Writer: endpoint, Dest: resolved, OriginalDest: original}
				if err := wrapped.WriteMultiBuffer(data); err != nil {
					t.Fatal(err)
				}
				if len(endpoint.data) != len(data) || endpoint.data[0] != data[0] {
					t.Fatal("write changed buffer ownership")
				}
			}
			if data[0].UDP.Address != to || data[0].UDP.Port != 443 || data[0].UDP.Network != net.Network_UDP {
				t.Fatal("matched address remapping or port/network changed")
			}
			if data[1].UDP.Address != other || data[1].UDP.Port != 53 || data[2].UDP != nil {
				t.Fatal("unmatched metadata changed")
			}
			for i, want := range []string{"matched payload", "other payload", "plain payload"} {
				if string(data[i].Bytes()) != want {
					t.Fatalf("payload %d changed", i)
				}
			}
		})
	}
}
