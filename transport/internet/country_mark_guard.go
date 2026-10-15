package internet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"go4.org/netipx"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const (
	countryMarkAssetMaxBytes    = 32 << 20
	countryMarkMaxPrefixes      = 2000000
	countryMarkRetainedMaxBytes = 16 << 20
	countryMarkStartupBudget    = 5 * time.Second
)

type countryMarkIndex struct {
	ru, private, nonRU *netipx.IPSet
	prefixCount        int
	retainedBytes      uintptr
}

var countryMarkLoadGate = make(chan struct{}, 1)

var countryMarkCache struct {
	hash  string
	index *countryMarkIndex
}

func validateCountryMarkGuardFields(c *CountryMarkGuard) error {
	if c == nil || c.RuMark == 0 || c.NonRuMark == 0 || c.RuMark == c.NonRuMark || c.RuMark > math.MaxInt32 || c.NonRuMark > math.MaxInt32 {
		return errors.New("country mark guard requires distinct positive int32 marks")
	}
	if c.GeoipFile != "geoip.dat" {
		return errors.New("country mark guard requires the geoip.dat asset")
	}
	digest, err := hex.DecodeString(c.GeoipSha256)
	if err != nil || len(digest) != sha256.Size || c.GeoipSha256 != strings.ToLower(c.GeoipSha256) {
		return errors.New("country mark guard requires a lowercase SHA256 pin")
	}
	return nil
}

// PrepareCountryMarkGuard fails before traffic on unsupported platforms or
// invalid assets. A single immutable pinned index is shared; no per-dial DNS.
func PrepareCountryMarkGuard(ctx context.Context, c *CountryMarkGuard) error {
	_, err := loadCountryMarkGuard(ctx, c)
	return err
}

func loadCountryMarkGuard(ctx context.Context, c *CountryMarkGuard) (*countryMarkIndex, error) {
	if err := validateCountryMarkGuardFields(c); err != nil {
		return nil, err
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("country mark guard requires Linux TCP SO_MARK")
	}
	budget, cancel := context.WithTimeout(ctx, countryMarkStartupBudget)
	defer cancel()
	select {
	case countryMarkLoadGate <- struct{}{}:
		defer func() { <-countryMarkLoadGate }()
	case <-budget.Done():
		return nil, budget.Err()
	}
	if err := budget.Err(); err != nil {
		return nil, err
	}
	if countryMarkCache.index != nil && countryMarkCache.hash == c.GeoipSha256 {
		return countryMarkCache.index, nil
	}
	info, err := filesystem.StatAsset(c.GeoipFile)
	if err != nil || info.Size() <= 0 || info.Size() > countryMarkAssetMaxBytes {
		return nil, errors.New("country mark guard asset unavailable or exceeds 32MiB")
	}
	reader, err := filesystem.OpenAsset(c.GeoipFile)
	if err != nil {
		return nil, errors.New("country mark guard asset unavailable")
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, countryMarkAssetMaxBytes+1))
	if err != nil || len(data) > countryMarkAssetMaxBytes {
		return nil, errors.New("country mark guard asset read failed or oversized")
	}
	index, err := buildCountryMarkIndex(budget, data, c.GeoipSha256)
	if err != nil {
		return nil, err
	}
	countryMarkCache.hash = c.GeoipSha256
	countryMarkCache.index = index
	return index, nil
}

// Stream one protobuf GeoIP entry at a time. Large GeoIPList object graphs are
// not retained; byte, prefix, elapsed and compact-index bounds are explicit.
func buildCountryMarkIndex(ctx context.Context, data []byte, pin string) (*countryMarkIndex, error) {
	if len(data) == 0 || len(data) > countryMarkAssetMaxBytes {
		return nil, errors.New("country mark guard asset size invalid")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != pin {
		return nil, errors.New("country mark guard asset SHA256 mismatch")
	}
	allowed := make(map[string]bool, 249)
	for _, code := range strings.Fields(countryMarkISO249) {
		allowed[code] = true
	}
	var ru, private, foreign netipx.IPSetBuilder
	count, ruCount, foreignCount := 0, 0, 0
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		number, wire, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, errors.New("country mark guard invalid asset protobuf")
		}
		data = data[n:]
		if number != 1 || wire != protowire.BytesType {
			return nil, errors.New("country mark guard unexpected asset protobuf field")
		}
		body, n := protowire.ConsumeBytes(data)
		if n < 0 {
			return nil, errors.New("country mark guard invalid asset entry")
		}
		data = data[n:]
		code, cidrs, scanErr := scanCountryMarkEntry(ctx, body)
		if scanErr != nil {
			return nil, scanErr
		}
		isRU, isPrivate := code == "RU", code == "PRIVATE"
		if !allowed[code] && !isPrivate {
			continue
		}
		if cidrs > countryMarkMaxPrefixes-count {
			return nil, errors.New("country mark guard prefix bound exceeded before decode")
		}
		entry := new(geodata.GeoIP)
		if proto.Unmarshal(body, entry) != nil {
			return nil, errors.New("country mark guard invalid GeoIP entry")
		}
		if entry.GetReverseMatch() {
			return nil, errors.New("country mark guard rejects inverse country/private entries")
		}
		for _, cidr := range entry.GetCidr() {
			count++
			if count > countryMarkMaxPrefixes {
				return nil, errors.New("country mark guard prefix bound exceeded")
			}
			if count%1024 == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			address, ok := netip.AddrFromSlice(cidr.GetIp())
			if !ok {
				return nil, errors.New("country mark guard invalid country address")
			}
			prefix := netip.PrefixFrom(address.Unmap(), int(cidr.GetPrefix()))
			if !prefix.IsValid() {
				return nil, errors.New("country mark guard invalid country prefix")
			}
			switch {
			case isRU:
				ru.AddPrefix(prefix)
				ruCount++
			case isPrivate:
				private.AddPrefix(prefix)
			default:
				foreign.AddPrefix(prefix)
				foreignCount++
			}
		}
	}
	if ruCount == 0 || foreignCount == 0 {
		return nil, errors.New("country mark guard requires RU and positive non-RU coverage")
	}
	r, err := ru.IPSet()
	if err != nil {
		return nil, errors.New("country mark guard invalid RU index")
	}
	p, err := private.IPSet()
	if err != nil {
		return nil, errors.New("country mark guard invalid private index")
	}
	f, err := foreign.IPSet()
	if err != nil {
		return nil, errors.New("country mark guard invalid country index")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	size := uintptr(len(r.Ranges())+len(p.Ranges())+len(f.Ranges())) * unsafe.Sizeof(netipx.IPRange{})
	if size > countryMarkRetainedMaxBytes {
		return nil, errors.New("country mark guard compact index exceeds 16MiB")
	}
	return &countryMarkIndex{ru: r, private: p, nonRU: f, prefixCount: count, retainedBytes: size}, nil
}

// Inspect bounded wire metadata before allocating repeated CIDR object graphs.
// Unknown pseudo/provider entries never enter a positive index or full decode.
func scanCountryMarkEntry(ctx context.Context, body []byte) (string, int, error) {
	code, count, fields := "", 0, 0
	for len(body) > 0 {
		fields++
		if fields%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return "", 0, err
			}
		}
		number, wire, n := protowire.ConsumeTag(body)
		if n < 0 {
			return "", 0, errors.New("country mark guard malformed country field")
		}
		body = body[n:]
		if number == 1 {
			if wire != protowire.BytesType {
				return "", 0, errors.New("country mark guard malformed country code")
			}
			value, n := protowire.ConsumeBytes(body)
			if n < 0 || len(value) > 128 {
				return "", 0, errors.New("country mark guard invalid country code")
			}
			code = strings.ToUpper(string(value))
			body = body[n:]
			continue
		}
		if number == 2 {
			if wire != protowire.BytesType {
				return "", 0, errors.New("country mark guard malformed CIDR field")
			}
			count++
			if count > countryMarkMaxPrefixes {
				return "", 0, errors.New("country mark guard per-entry prefix bound exceeded")
			}
		}
		n = protowire.ConsumeFieldValue(number, wire, body)
		if n < 0 {
			return "", 0, errors.New("country mark guard malformed country field")
		}
		body = body[n:]
	}
	return code, count, nil
}

var countryMarkReserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("100:0:0:1::/64"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"), netip.MustParsePrefix("5f00::/16"),
}

func (i *countryMarkIndex) actualSocketMark(network, address string, c *CountryMarkGuard) (int32, error) {
	if network != "tcp4" {
		return 0, errors.New("country mark guard requires TCP IPv4 socket")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return 0, errors.New("country mark guard invalid socket address")
	}
	number, portErr := strconv.Atoi(port)
	if portErr != nil || number < 1 || number > 65535 {
		return 0, errors.New("country mark guard invalid socket port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return 0, errors.New("country mark guard requires literal socket IP")
	}
	ip = ip.Unmap()
	if !ip.Is4() {
		return 0, errors.New("country mark guard socket family mismatch")
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return 0, errors.New("country mark guard rejects private/reserved destination")
	}
	for _, prefix := range countryMarkReserved {
		if prefix.Contains(ip) {
			return 0, errors.New("country mark guard rejects reserved destination")
		}
	}
	if i == nil || i.ru == nil || i.private == nil || i.nonRU == nil {
		return 0, errors.New("country mark guard index unavailable")
	}
	if i.private.Contains(ip) {
		return 0, errors.New("country mark guard rejects private asset destination")
	}
	if i.ru.Contains(ip) {
		return int32(c.RuMark), nil
	}
	if i.nonRU.Contains(ip) {
		return int32(c.NonRuMark), nil
	}
	return 0, errors.New("country mark guard destination country unknown")
}

// Each actual GoDialer candidate reaches this before connect. Ordinary socket
// options run first and the proven mark last; both callback layers fail closed.
func countryMarkControl(i *countryMarkIndex, c *CountryMarkGuard, network, address string, raw syscall.RawConn, ordinary func(uintptr) error, setMark func(uintptr, int32) error) error {
	mark, err := i.actualSocketMark(network, address, c)
	if err != nil {
		return err
	}
	var inner error
	err = raw.Control(func(fd uintptr) {
		if ordinary != nil {
			inner = ordinary(fd)
			if inner != nil {
				return
			}
		}
		inner = setMark(fd, mark)
	})
	if err != nil {
		return fmt.Errorf("country mark guard socket control failed: %w", err)
	}
	if inner != nil {
		return fmt.Errorf("country mark guard socket options failed: %w", inner)
	}
	return nil
}

func validateCountryMarkSocketPath(c *SocketConfig) error {
	if c.DialerProxy != "" || c.Interface != "" || len(c.CustomSockopt) > 0 || c.TcpMptcp || c.Tproxy != SocketConfig_Off || len(Controllers) > 0 {
		return errors.New("country mark guard rejects unsupported socket routing paths")
	}
	return nil
}
