package forwardingdrain

import (
	"context"
	"net"

	"github.com/xtls/xray-core/transport/internet/stat"
)

// Connection carries native accepted-socket lineage across the transport callback
// signature. The wrapper does not grant authentication or replace the real socket.
type Connection struct {
	net.Conn
	Ctx context.Context
	Raw net.Conn
}

func ConnectionContext(c net.Conn, fallback context.Context) context.Context {
	if owned, ok := c.(*Connection); ok {
		return owned.Ctx
	}
	return fallback
}

func RawConnection(c net.Conn) net.Conn {
	if wrapped, ok := c.(*stat.CounterConnection); ok {
		return RawConnection(wrapped.Connection)
	}
	if owned, ok := c.(*Connection); ok {
		return owned.Raw
	}
	return c
}
