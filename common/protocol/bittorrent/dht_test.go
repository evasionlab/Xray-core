package bittorrent

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
)

func encodeDHT(v any) []byte {
	switch x := v.(type) {
	case string:
		return []byte(fmt.Sprintf("%d:%s", len(x), x))
	case int:
		return []byte(fmt.Sprintf("i%de", x))
	case []any:
		b := []byte{'l'}
		for _, item := range x {
			b = append(b, encodeDHT(item)...)
		}
		return append(b, 'e')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for key := range x {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		b := []byte{'d'}
		for _, key := range keys {
			b = append(b, encodeDHT(key)...)
			b = append(b, encodeDHT(x[key])...)
		}
		return append(b, 'e')
	default:
		panic("invalid fixture")
	}
}

func dhtQuery(method string, fields map[string]any) map[string]any {
	a := map[string]any{"id": "abcdefghij0123456789"}
	for k, v := range fields {
		a[k] = v
	}
	return map[string]any{"t": "aa", "y": "q", "q": method, "a": a}
}

func TestSniffDHT(t *testing.T) {
	id := "mnopqrstuvwxyz123456"
	tests := map[string]any{
		"ping":                          dhtQuery("ping", nil),
		"find_node":                     dhtQuery("find_node", map[string]any{"target": id}),
		"get_peers":                     dhtQuery("get_peers", map[string]any{"info_hash": id}),
		"announce_peer":                 dhtQuery("announce_peer", map[string]any{"info_hash": id, "port": 6881, "token": "opaque"}),
		"announce_implied_port":         dhtQuery("announce_peer", map[string]any{"info_hash": id, "implied_port": 1, "port": 0, "token": "opaque"}),
		"ping_response":                 map[string]any{"t": "aa", "y": "r", "r": map[string]any{"id": id}},
		"nodes_response":                map[string]any{"t": "aa", "y": "r", "r": map[string]any{"id": id, "nodes": strings.Repeat("n", 26), "nodes6": strings.Repeat("n", 38)}},
		"peers_response":                map[string]any{"t": "aa", "y": "r", "r": map[string]any{"id": id, "token": "opaque", "values": []any{strings.Repeat("p", 6), strings.Repeat("p", 18)}}},
		"error":                         map[string]any{"t": "aa", "y": "e", "e": []any{203, "invalid arguments"}},
		"binary_txid_version_extension": map[string]any{"t": "\x00\xff", "y": "r", "v": "UT\x01\x02", "r": map[string]any{"id": id}, "ro": 1},
	}
	for name, v := range tests {
		t.Run(name, func(t *testing.T) {
			h, err := SniffDHT(encodeDHT(v))
			if err != nil || h == nil || h.Protocol() != "bittorrent" {
				t.Fatalf("not recognized: %v", err)
			}
		})
	}
}

func TestSniffDHTRejectsNonDHT(t *testing.T) {
	id := "mnopqrstuvwxyz123456"
	tests := map[string][]byte{
		"empty": nil, "random": bytes.Repeat([]byte{0x9a}, 96),
		"dns":                    {0x41, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 2, 'c', 'o', 0, 0, 1, 0, 1},
		"stun":                   {0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"rtp":                    {0x80, 0x60, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1},
		"quic":                   {0xc0, 0, 0, 0, 1, 0, 0, 0, 0},
		"generic_bencode":        encodeDHT(map[string]any{"name": "BitTorrent", "payload": "1:y1:q"}),
		"unknown_method":         encodeDHT(dhtQuery("rpc", nil)),
		"missing_id":             encodeDHT(map[string]any{"t": "aa", "y": "q", "q": "ping", "a": map[string]any{}}),
		"short_id":               encodeDHT(dhtQuery("ping", map[string]any{"id": "short"})),
		"missing_target":         encodeDHT(dhtQuery("find_node", nil)),
		"missing_infohash":       encodeDHT(dhtQuery("get_peers", nil)),
		"announce_bad_port":      encodeDHT(dhtQuery("announce_peer", map[string]any{"info_hash": id, "token": "token", "port": 65536})),
		"announce_missing_token": encodeDHT(dhtQuery("announce_peer", map[string]any{"info_hash": id, "port": 6881})),
		"response_missing_id":    encodeDHT(map[string]any{"t": "aa", "y": "r", "r": map[string]any{}}),
		"bad_nodes":              encodeDHT(map[string]any{"t": "aa", "y": "r", "r": map[string]any{"id": id, "nodes": "short"}}),
		"bad_peer":               encodeDHT(map[string]any{"t": "aa", "y": "r", "r": map[string]any{"id": id, "values": []any{"short"}}}),
		"unknown_error_code":     encodeDHT(map[string]any{"t": "aa", "y": "e", "e": []any{999, "generic RPC error"}}),
		"error_wrong_types":      encodeDHT(map[string]any{"t": "aa", "y": "e", "e": []any{"203", "error"}}),
		"conflicting_envelope":   encodeDHT(map[string]any{"t": "aa", "y": "q", "q": "ping", "a": map[string]any{"id": id}, "r": map[string]any{"id": id}}),
		"huge_length":            []byte("d9999999999999999999999:x"),
		"duplicate_key":          []byte("d1:t2:aa1:t2:bb1:y1:ee"),
		"negative_zero":          []byte("d1:eli-0e1:xe1:t2:aa1:y1:ee"),
		"oversize":               bytes.Repeat([]byte{'d'}, maxDHTPacket+1),
	}
	ping := encodeDHT(dhtQuery("ping", nil))
	tests["trailing_data"] = append(append([]byte(nil), ping...), 'x')
	tests["truncated"] = ping[:len(ping)-1]
	tests["deep"] = []byte("d1:x" + strings.Repeat("l", maxDHTDepth+1) + "0:" + strings.Repeat("e", maxDHTDepth+1) + "e")
	tests["too_many_values"] = []byte("d1:xl" + strings.Repeat("0:", maxDHTValues) + "ee")
	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			if h, err := SniffDHT(b); h != nil || err == nil {
				t.Fatal("incorrectly recognized as bittorrent")
			}
		})
	}
}

func TestSniffBittorrentPartialHeader(t *testing.T) {
	header := []byte("\x13BitTorrent protocol")
	if _, err := SniffBittorrent(nil); err != common.ErrNoClue {
		t.Fatalf("empty: %v", err)
	}
	for n := 1; n < len(header); n++ {
		if _, err := SniffBittorrent(header[:n]); err != protocol.ErrProtoNeedMoreData {
			t.Fatalf("matching prefix length %d: %v", n, err)
		}
		mismatch := append([]byte(nil), header[:n]...)
		mismatch[n-1] ^= 0xff
		if h, err := SniffBittorrent(mismatch); h != nil || err == nil || err == protocol.ErrProtoNeedMoreData || err == common.ErrNoClue {
			t.Fatalf("nonmatching prefix length %d: %v", n, err)
		}
	}
	for _, b := range [][]byte{header, append(append([]byte(nil), header...), make([]byte, 48)...)} {
		if h, err := SniffBittorrent(b); h == nil || err != nil {
			t.Fatalf("complete handshake: %v", err)
		}
	}
}

func FuzzSniffDHT(f *testing.F) {
	f.Add(encodeDHT(dhtQuery("ping", nil)))
	f.Add([]byte("d1:eli201e5:errore1:t2:aa1:y1:ee"))
	f.Add([]byte{0x41, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := SniffDHT(b)
		if h != nil && err != nil {
			t.Fatal("header with error")
		}
	})
}
