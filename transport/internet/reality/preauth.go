package reality

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
)

// ServerWithContext applies the existing unauthenticated session handshake budget
// before REALITY allocates a camouflage connection. The user level is not known
// until authentication, so the same level-zero policy used before VLESS decoding
// applies here.
func ServerWithContext(ctx context.Context, c net.Conn, config *goreality.Config) (net.Conn, error) {
	timeout := policy.SessionDefault().Timeouts.Handshake
	if instance := core.FromContext(ctx); instance != nil {
		if manager, ok := instance.GetFeature(policy.ManagerType()).(policy.Manager); ok {
			timeout = manager.ForLevel(0).Timeouts.Handshake
		}
	}
	return serverWithHandshakeBudget(ctx, c, config, timeout)
}

func serverWithHandshakeBudget(ctx context.Context, c net.Conn, config *goreality.Config, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	if err := c.SetReadDeadline(deadline); err != nil {
		c.Close()
		return nil, err
	}
	prefix, err := readClientHelloPrefix(c)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("REALITY: failed to receive client hello within handshake budget: %w", err)
	}
	// The budget belongs to admission, not to established VPN sessions or ordinary
	// TLS camouflage forwarding, which can legitimately outlive this deadline.
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		c.Close()
		return nil, err
	}
	connectionConfig := *config
	connectionConfig.DialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		dialContext, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		return config.DialContext(dialContext, network, address)
	}
	realityConn, err := goreality.Server(ctx, &prefetchedConn{Conn: c, prefix: prefix}, &connectionConfig)
	if err != nil {
		return nil, err
	}
	return &Conn{Conn: realityConn}, nil
}

const (
	// Match the TLS implementation's record and ClientHello handshake limits.
	maxClientHelloSize = 65536
	maxTLSRecordSize   = 16384 + 2048
	// A legal ClientHello may be fragmented into one-byte TLS records. Include
	// their five-byte headers and the final record without unbounded buffering.
	maxClientHelloWireSize = 6*(maxClientHelloSize+4) + maxTLSRecordSize + 5
)

// readClientHelloPrefix retains exact TLS wire bytes, including record boundaries.
// Non-TLS or malformed prefixes are handed to the existing camouflage behavior;
// incomplete TLS records/ClientHello messages must finish within the read budget.
func readClientHelloPrefix(r io.Reader) ([]byte, error) {
	var wire []byte
	var helloHeader [4]byte
	helloBytes, headerBytes, helloLength := 0, 0, -1
	read := func(n int) ([]byte, error) {
		if len(wire)+n > maxClientHelloWireSize {
			return nil, fmt.Errorf("client hello exceeds TLS wire size limit")
		}
		start := len(wire)
		wire = append(wire, make([]byte, n)...)
		_, err := io.ReadFull(r, wire[start:])
		return wire[start:], err
	}
	for {
		first, err := read(1)
		if err != nil {
			return nil, err
		}
		if first[0] != 22 { // Preserve non-handshake/plaintext camouflage traffic.
			return wire, nil
		}
		header, err := read(4)
		if err != nil {
			return nil, err
		}
		length := int(binary.BigEndian.Uint16(header[2:]))
		if header[0] != 3 || length == 0 || length > maxTLSRecordSize {
			return wire, nil
		}
		payload, err := read(length)
		if err != nil {
			return nil, err
		}
		if headerBytes < len(helloHeader) {
			headerBytes += copy(helloHeader[headerBytes:], payload)
		}
		helloBytes += len(payload)
		if headerBytes == len(helloHeader) && helloLength < 0 {
			helloLength = int(helloHeader[1])<<16 | int(helloHeader[2])<<8 | int(helloHeader[3])
			if helloHeader[0] != 1 || helloLength > maxClientHelloSize {
				return wire, nil
			}
		}
		if helloLength >= 0 && helloBytes >= helloLength+4 {
			return wire, nil
		}
	}
}

// prefetchedConn replays the admission bytes and then delegates directly. Keep
// half-close and io.Copy fast paths available to REALITY's camouflage forwarding.
type prefetchedConn struct {
	net.Conn
	prefix []byte
}

func (c *prefetchedConn) Read(p []byte) (int, error) {
	if len(c.prefix) != 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.prefix = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *prefetchedConn) WriteTo(w io.Writer) (int64, error) {
	var n int64
	if len(c.prefix) != 0 {
		written, err := w.Write(c.prefix)
		n = int64(written)
		c.prefix = c.prefix[written:]
		if err != nil {
			return n, err
		}
		if len(c.prefix) != 0 {
			return n, io.ErrShortWrite
		}
		c.prefix = nil
	}
	written, err := io.Copy(w, c.Conn)
	return n + written, err
}

func (c *prefetchedConn) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(c.Conn, r)
}

func (c *prefetchedConn) CloseWrite() error {
	connection := c.Conn
	if raw, ok := connection.(interface{ Raw() net.Conn }); ok {
		connection = raw.Raw() // Preserve PROXY-protocol half-close behavior.
	}
	if closer, ok := connection.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return fmt.Errorf("REALITY: connection does not support half-close")
}
