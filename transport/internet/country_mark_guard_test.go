package internet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	"google.golang.org/protobuf/proto"
)

func countryFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	entry := func(code, prefix string) *geodata.GeoIP {
		p := netip.MustParsePrefix(prefix)
		ip := p.Addr().AsSlice()
		return &geodata.GeoIP{Code: code, Cidr: []*geodata.CIDR{{Ip: ip, Prefix: uint32(p.Bits())}}}
	}
	data, err := proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{entry("RU", "77.0.0.0/8"), entry("RU", "2a02:6b8::/32"), entry("US", "2606:4700::/32"), entry("US", "77.0.0.0/8"), entry("US", "8.8.8.0/24"), entry("CA", "162.159.0.0/16"), entry("PRIVATE", "8.8.8.128/25"), entry("ZZ", "9.9.9.0/24"), entry("XX", "11.0.0.0/8"), entry("XK", "12.0.0.0/8"), entry("TEST", "13.0.0.0/8")}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:])
}

func fixtureIndex(t *testing.T) (*countryMarkIndex, *CountryMarkGuard) {
	t.Helper()
	data, hash := countryFixture(t)
	index, err := buildCountryMarkIndex(context.Background(), data, hash)
	if err != nil {
		t.Fatal(err)
	}
	return index, &CountryMarkGuard{RuMark: 41060, NonRuMark: 41014, GeoipFile: "geoip.dat", GeoipSha256: hash}
}

type countryRawConn struct {
	calls int
	err   error
}

func (c *countryRawConn) Control(f func(uintptr)) error {
	c.calls++
	if c.err != nil {
		return c.err
	}
	f(19)
	return nil
}
func (*countryRawConn) Read(func(uintptr) bool) error  { return errors.New("not used") }
func (*countryRawConn) Write(func(uintptr) bool) error { return errors.New("not used") }

func TestCountryMarkActualSocketCountriesAndUnknownClosed(t *testing.T) {
	index, cfg := fixtureIndex(t)
	for _, tc := range []struct {
		network, address string
		mark             int32
	}{
		{"tcp4", "77.1.2.3:443", 41060},
		{"tcp4", "8.8.8.8:443", 41014},
		{"tcp4", "162.159.200.1:443", 41014},
		{"tcp4", "8.8.8.200:443", 0},
		{"tcp4", "9.9.9.9:443", 0},
		{"tcp4", "11.1.2.3:443", 0},
		{"tcp4", "12.1.2.3:443", 0},
		{"tcp4", "13.1.2.3:443", 0},
		{"tcp4", "14.1.2.3:443", 0},
		{"tcp4", "127.0.0.1:443", 0},
		{"tcp4", "10.0.0.1:443", 0},
		{"tcp4", "192.0.2.1:443", 0},
		{"tcp4", "youtube.com:443", 0},
		{"tcp4", "8.8.8.8:bad", 0},
		{"tcp4", "8.8.8.8:0", 0},
		{"tcp6", "8.8.8.8:443", 0},
		{"udp4", "8.8.8.8:443", 0},
		{"tcp", "8.8.8.8:443", 0},
		{"tcp6", "[fe80::1%eth0]:443", 0},
		{"tcp6", "[2001:db8::1]:443", 0},
		{"tcp6", "[2a00:1450:4001:81b::200e]:443", 0},
		{"tcp6", "[2a02:6b8::1]:443", 0},
		{"tcp6", "[2606:4700::1111]:443", 0},
		{"tcp6", "[::ffff:77.1.2.3]:443", 0},
	} {
		t.Run(tc.network+tc.address, func(t *testing.T) {
			mark, err := index.actualSocketMark(tc.network, tc.address, cfg)
			if tc.mark == 0 {
				if err == nil {
					t.Fatal("unproven candidate admitted")
				}
				return
			}
			if err != nil || mark != tc.mark {
				t.Fatalf("mark=%d err=%v want=%d", mark, err, tc.mark)
			}
		})
	}
}

func TestCountryMarkActualCandidateOverridesDNSViewAndRetries(t *testing.T) {
	index, cfg := fixtureIndex(t)
	var applied []int32
	// A domain classifier may have seen foreign answers. The real RU socket must
	// still receive RU mark last, even when ordinary sockopt used foreign mark.
	for _, candidate := range []string{"77.1.2.3:443", "8.8.8.8:443"} {
		raw := new(countryRawConn)
		err := countryMarkControl(index, cfg, "tcp4", candidate, raw,
			func(uintptr) error { applied = append(applied, 41014); return nil },
			func(fd uintptr, mark int32) error {
				if fd != 19 {
					t.Fatal("wrong fd")
				}
				applied = append(applied, mark)
				return nil
			})
		if err != nil || raw.calls != 1 {
			t.Fatalf("candidate failed: %v", err)
		}
	}
	want := []int32{41014, 41060, 41014, 41014}
	for n := range want {
		if applied[n] != want[n] {
			t.Fatal("candidate mark order or retry not reevaluated")
		}
	}
}

func TestCountryMarkControlAndInnerMarkErrorsPropagate(t *testing.T) {
	index, cfg := fixtureIndex(t)
	sentinel := errors.New("controlled failure")
	for _, kind := range []string{"raw", "ordinary", "mark"} {
		t.Run(kind, func(t *testing.T) {
			raw := new(countryRawConn)
			if kind == "raw" {
				raw.err = sentinel
			}
			marks := 0
			err := countryMarkControl(index, cfg, "tcp4", "8.8.8.8:443", raw,
				func(uintptr) error {
					if kind == "ordinary" {
						return sentinel
					}
					return nil
				},
				func(uintptr, int32) error {
					marks++
					if kind == "mark" {
						return sentinel
					}
					return nil
				})
			if !errors.Is(err, sentinel) {
				t.Fatal("socket failure ignored")
			}
			if kind != "mark" && marks != 0 {
				t.Fatal("continued after prior failure")
			}
		})
	}
	raw := new(countryRawConn)
	if err := countryMarkControl(index, cfg, "tcp4", "9.9.9.9:443", raw, nil, func(uintptr, int32) error { t.Fatal("unknown socket touched"); return nil }); err == nil || raw.calls != 0 {
		t.Fatal("unknown touched socket")
	}
}

func TestCountryMarkPinnedAssetBoundsAndCountries(t *testing.T) {
	data, hash := countryFixture(t)
	if len(strings.Fields(countryMarkISO249)) != 249 {
		t.Fatal("country admission set drift")
	}
	for _, invalid := range []string{"", strings.Repeat("a", 64), strings.ToUpper(hash)} {
		c := &CountryMarkGuard{RuMark: 41060, NonRuMark: 41014, GeoipFile: "geoip.dat", GeoipSha256: invalid}
		if invalid == strings.Repeat("a", 64) {
			if _, err := buildCountryMarkIndex(context.Background(), data, invalid); err == nil {
				t.Fatal("wrong pin accepted")
			}
			continue
		}
		if err := validateCountryMarkGuardFields(c); err == nil {
			t.Fatal("invalid pin shape accepted")
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := buildCountryMarkIndex(canceled, data, hash); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	oversized := make([]byte, countryMarkAssetMaxBytes+1)
	if _, err := buildCountryMarkIndex(context.Background(), oversized, hash); err == nil {
		t.Fatal("oversized accepted")
	}
	for _, mode := range []string{"inverseRU", "inverseForeign", "missingRU", "invalidIP"} {
		entry := &geodata.GeoIP{Code: "RU", Cidr: []*geodata.CIDR{{Ip: []byte{77, 0, 0, 0}, Prefix: 8}}}
		foreign := &geodata.GeoIP{Code: "US", Cidr: []*geodata.CIDR{{Ip: []byte{8, 8, 8, 0}, Prefix: 24}}}
		switch mode {
		case "inverseRU":
			entry.ReverseMatch = true
		case "inverseForeign":
			foreign.ReverseMatch = true
		case "missingRU":
			entry.Code = "ZZ"
		case "invalidIP":
			foreign.Cidr[0].Ip = []byte{1}
		}
		wire, _ := proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{entry, foreign}})
		sum := sha256.Sum256(wire)
		if _, err := buildCountryMarkIndex(context.Background(), wire, hex.EncodeToString(sum[:])); err == nil {
			t.Fatalf("invalid %s asset admitted", mode)
		}
	}
}

func TestCountryMarkActualGoDialerPreconnectAndLegacyDefault(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	destination := xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(func() int { n, _ := strconv.Atoi(port); return n }()))
	dialer := new(DefaultSystemDialer)
	legacy, err := dialer.Dial(context.Background(), nil, destination, nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	accepted.Close()
	data, hash := countryFixture(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "geoip.dat"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_LOCATION_ASSET", dir)
	cfg := &SocketConfig{CountryMarkGuard: &CountryMarkGuard{RuMark: 41060, NonRuMark: 41014, GeoipFile: "geoip.dat", GeoipSha256: hash}}
	_, err = dialer.Dial(context.Background(), nil, destination, cfg)
	if err == nil {
		t.Fatal("guard allowed loopback")
	}
	tcp := listener.(*net.TCPListener)
	tcp.SetDeadline(time.Now().Add(30 * time.Millisecond))
	if conn, err := listener.Accept(); err == nil {
		conn.Close()
		t.Fatal("guard connected before rejection")
	}
	if _, err = dialer.Dial(context.Background(), nil, xnet.UDPDestination(xnet.ParseAddress("8.8.8.8"), 53), cfg); err == nil {
		t.Fatal("guarded UDP permitted")
	}
	if runtime.GOOS != "linux" && !strings.Contains(err.Error(), "TCP") {
		t.Fatal("nonTCP rejection missing")
	}
}

func TestCountryMarkActualAssetBudget(t *testing.T) {
	path := os.Getenv("XRAY_COUNTRY_MARK_TEST_ASSET")
	if path == "" {
		t.Skip("set XRAY_COUNTRY_MARK_TEST_ASSET to measured public pinned asset")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	var peak atomic.Uint64
	peak.Store(baseline.HeapAlloc)
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				var s runtime.MemStats
				runtime.ReadMemStats(&s)
				for {
					old := peak.Load()
					if old >= s.HeapAlloc || peak.CompareAndSwap(old, s.HeapAlloc) {
						break
					}
				}
			}
		}
	}()
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), countryMarkStartupBudget)
	defer cancel()
	index, err := buildCountryMarkIndex(ctx, data, hex.EncodeToString(sum[:]))
	elapsed := time.Since(started)
	close(done)
	<-finished
	if err != nil {
		t.Fatal(err)
	}
	if elapsed > countryMarkStartupBudget || peak.Load() > 512<<20 || index.retainedBytes > countryMarkRetainedMaxBytes {
		t.Fatalf("budget exceeded: elapsed=%s peak=%d retained=%d", elapsed, peak.Load(), index.retainedBytes)
	}
	t.Logf("assetBytes=%d prefixCount=%d startup=%s peakHeapBytes=%d retainedIndexBytes=%d hash=%s", len(data), index.prefixCount, elapsed, peak.Load(), index.retainedBytes, hex.EncodeToString(sum[:]))
}

func TestCountryMarkGuardRejectsDialerBypasses(t *testing.T) {
	_, cfg := fixtureIndex(t)
	target := xnet.TCPDestination(xnet.ParseAddress("8.8.8.8"), 443)
	for _, socket := range []*SocketConfig{{CountryMarkGuard: cfg, DialerProxy: "proxy"}, {CountryMarkGuard: cfg, Interface: "wg0"}, {CountryMarkGuard: cfg, TcpMptcp: true}, {CountryMarkGuard: cfg, CustomSockopt: []*CustomSockopt{{}}}, {CountryMarkGuard: cfg, Tproxy: SocketConfig_TProxy}} {
		if _, err := DialSystem(context.Background(), target, socket); err == nil {
			t.Fatal("guard routing bypass admitted")
		}
		if _, err := new(DefaultSystemDialer).Dial(context.Background(), nil, target, socket); err == nil {
			t.Fatal("direct system dialer routing bypass admitted")
		}
	}
	original := effectiveSystemDialer
	UseAlternativeSystemDialer(&SimpleSystemDialer{})
	defer func() { effectiveSystemDialer = original }()
	if _, err := DialSystem(context.Background(), target, &SocketConfig{CountryMarkGuard: cfg}); err == nil {
		t.Fatal("unsupported alternative dialer admitted")
	}
}

func TestCountryMarkPrefixBoundBeforeObjectDecode(t *testing.T) {
	// Millions of empty CIDR messages otherwise allocate large protobuf graphs.
	body := []byte{0x0a, 2, 'U', 'S'}
	for n := 0; n <= countryMarkMaxPrefixes; n++ {
		body = append(body, 0x12, 0)
	}
	if _, _, err := scanCountryMarkEntry(context.Background(), body); err == nil {
		t.Fatal("unbounded CIDR graph accepted")
	}
}

func TestCountryMarkExternalControllersRejected(t *testing.T) {
	_, cfg := fixtureIndex(t)
	original := Controllers
	Controllers = []func(string, string, syscall.RawConn) error{func(string, string, syscall.RawConn) error {
		t.Fatal("guard invoked uncontrolled socket controller")
		return nil
	}}
	defer func() { Controllers = original }()
	if _, err := new(DefaultSystemDialer).Dial(context.Background(), nil, xnet.TCPDestination(xnet.ParseAddress("8.8.8.8"), 443), &SocketConfig{CountryMarkGuard: cfg}); err == nil {
		t.Fatal("uncontrolled socket callback allowed")
	}
}
