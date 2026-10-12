package bittorrent

import "strconv"

// DHT uses one complete bencoded KRPC message per UDP datagram (BEP 5).
// Bound work and allocations before inspecting untrusted traffic. Oversized or
// unsupported messages remain unclassified; they are not grounds to block UDP.
const (
	maxDHTPacket = 4096
	maxDHTDepth  = 8
	maxDHTValues = 256
)

type dhtValue struct {
	kind    byte
	str     []byte
	integer int64
	dict    map[string]dhtValue
	list    []dhtValue
}

type dhtParser struct {
	data           []byte
	offset, values int
}

func (p *dhtParser) value(depth int) (dhtValue, bool) {
	if depth > maxDHTDepth || p.offset >= len(p.data) || p.values >= maxDHTValues {
		return dhtValue{}, false
	}
	p.values++
	c := p.data[p.offset]
	if c >= '0' && c <= '9' {
		start := p.offset
		for p.offset < len(p.data) && p.data[p.offset] >= '0' && p.data[p.offset] <= '9' {
			p.offset++
		}
		if p.offset >= len(p.data) || p.data[p.offset] != ':' || p.offset-start > 4 || (p.offset-start > 1 && p.data[start] == '0') {
			return dhtValue{}, false
		}
		n, err := strconv.Atoi(string(p.data[start:p.offset]))
		p.offset++
		if err != nil || n > len(p.data)-p.offset {
			return dhtValue{}, false
		}
		v := dhtValue{kind: 's', str: p.data[p.offset : p.offset+n]}
		p.offset += n
		return v, true
	}
	p.offset++
	switch c {
	case 'i':
		start := p.offset
		for p.offset < len(p.data) && p.data[p.offset] != 'e' {
			p.offset++
		}
		if p.offset >= len(p.data) || p.offset == start {
			return dhtValue{}, false
		}
		raw := p.data[start:p.offset]
		if raw[0] == '+' || (len(raw) > 1 && raw[0] == '0') || (raw[0] == '-' && (len(raw) < 2 || raw[1] == '0')) {
			return dhtValue{}, false
		}
		n, err := strconv.ParseInt(string(raw), 10, 64)
		p.offset++
		return dhtValue{kind: 'i', integer: n}, err == nil
	case 'd', 'l':
		v := dhtValue{kind: c}
		if c == 'd' {
			v.dict = make(map[string]dhtValue)
		}
		for p.offset < len(p.data) && p.data[p.offset] != 'e' {
			var key string
			if c == 'd' {
				k, ok := p.value(depth + 1)
				if !ok || k.kind != 's' {
					return dhtValue{}, false
				}
				key = string(k.str)
				if _, exists := v.dict[key]; exists {
					return dhtValue{}, false
				}
			}
			child, ok := p.value(depth + 1)
			if !ok {
				return dhtValue{}, false
			}
			if c == 'd' {
				v.dict[key] = child
			} else {
				v.list = append(v.list, child)
			}
		}
		if p.offset >= len(p.data) {
			return dhtValue{}, false
		}
		p.offset++
		return v, true
	}
	return dhtValue{}, false
}

func dhtString(v dhtValue, min, max int) bool {
	return v.kind == 's' && len(v.str) >= min && len(v.str) <= max
}
func dhtID(v dhtValue) bool { return dhtString(v, 20, 20) }

// SniffDHT recognizes structurally valid BEP 5 messages, not arbitrary bencode.
// Truncated UDP datagrams are invalid rather than requests for another datagram.
func SniffDHT(b []byte) (*SniffHeader, error) {
	if len(b) == 0 || len(b) > maxDHTPacket || b[0] != 'd' {
		return nil, errNotBittorrent
	}
	p := dhtParser{data: b}
	v, ok := p.value(0)
	if !ok || p.offset != len(b) || v.kind != 'd' || !dhtString(v.dict["t"], 1, 32) || !dhtString(v.dict["y"], 1, 1) {
		return nil, errNotBittorrent
	}
	// Conflicting message bodies are not valid KRPC envelopes.
	body := ""
	switch string(v.dict["y"].str) {
	case "q":
		body = "a"
	case "r":
		body = "r"
	case "e":
		body = "e"
	default:
		return nil, errNotBittorrent
	}
	for _, k := range []string{"a", "r", "e"} {
		if k != body {
			if _, exists := v.dict[k]; exists {
				return nil, errNotBittorrent
			}
		}
	}
	valid := false
	switch body {
	case "a":
		a := v.dict["a"]
		if a.kind != 'd' || !dhtID(a.dict["id"]) || !dhtString(v.dict["q"], 1, 32) {
			break
		}
		switch string(v.dict["q"].str) {
		case "ping":
			valid = true
		case "find_node":
			valid = dhtID(a.dict["target"])
		case "get_peers":
			valid = dhtID(a.dict["info_hash"])
		case "announce_peer":
			port := a.dict["port"]
			implied := a.dict["implied_port"]
			valid = dhtID(a.dict["info_hash"]) && dhtString(a.dict["token"], 1, 256) && ((port.kind == 'i' && port.integer > 0 && port.integer <= 65535) || (implied.kind == 'i' && implied.integer == 1))
		}
	case "r":
		r := v.dict["r"]
		valid = r.kind == 'd' && dhtID(r.dict["id"])
		for _, compact := range []struct {
			key  string
			size int
		}{{"nodes", 26}, {"nodes6", 38}} {
			if n, exists := r.dict[compact.key]; exists {
				valid = valid && n.kind == 's' && len(n.str)%compact.size == 0
			}
		}
		if peers, exists := r.dict["values"]; exists {
			valid = valid && peers.kind == 'l' && len(peers.list) > 0
			for _, peer := range peers.list {
				valid = valid && peer.kind == 's' && (len(peer.str) == 6 || len(peer.str) == 18)
			}
		}
		if token, exists := r.dict["token"]; exists {
			valid = valid && dhtString(token, 1, 256)
		}
	case "e":
		e := v.dict["e"]
		valid = e.kind == 'l' && len(e.list) == 2 && e.list[0].kind == 'i' && e.list[0].integer >= 201 && e.list[0].integer <= 204 && dhtString(e.list[1], 1, 256)
	}
	if !valid {
		return nil, errNotBittorrent
	}
	return &SniffHeader{}, nil
}
