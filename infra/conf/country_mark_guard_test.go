package conf_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

func TestCountryMarkGuardJSONValidation(t *testing.T) {
	for _, body := range []string{
		`{"countryMarkGuard":{"ruMark":41060,"nonRuMark":41014,"geoipFile":"geoip.dat","geoipSHA256":"bad"}}`,
		`{"countryMarkGuard":{"ruMark":41060,"nonRuMark":41060,"geoipFile":"geoip.dat","geoipSHA256":"` + strings.Repeat("a", 64) + `"}}`,
		`{"countryMarkGuard":{"ruMark":41060,"nonRuMark":41014,"geoipFile":"../private","geoipSHA256":"` + strings.Repeat("a", 64) + `"}}`,
		`{"countryMarkGuard":{"ruMark":41060,"nonRuMark":41014,"unexpected":true}}`,
		`{"countryMarkGuard":{"ruMark":-1,"nonRuMark":41014}}`,
		`{"dialerProxy":"other","countryMarkGuard":{"ruMark":41060,"nonRuMark":41014}}`,
		`{"interface":"wg0","countryMarkGuard":{"ruMark":41060,"nonRuMark":41014}}`,
	} {
		cfg := new(conf.SocketConfig)
		err := json.Unmarshal([]byte(body), cfg)
		if err == nil {
			_, err = cfg.Build()
		}
		if err == nil {
			t.Fatal("invalid guard configuration accepted")
		}
	}
	legacy := new(conf.SocketConfig)
	if err := json.Unmarshal([]byte(`{"mark":41014}`), legacy); err != nil {
		t.Fatal(err)
	}
	built, err := legacy.Build()
	if err != nil || built.GetCountryMarkGuard() != nil || built.GetMark() != 41014 {
		t.Fatal("legacy socket config changed")
	}
}

func TestCountryMarkGuardProtobufRoundtrip(t *testing.T) {
	cfg := &internet.SocketConfig{CountryMarkGuard: &internet.CountryMarkGuard{RuMark: 41060, NonRuMark: 41014, GeoipFile: "geoip.dat", GeoipSha256: strings.Repeat("a", 64)}}
	wire, err := proto.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	restored := new(internet.SocketConfig)
	if err = proto.Unmarshal(wire, restored); err != nil || !proto.Equal(cfg, restored) {
		t.Fatal("country mark guard lost in transport config")
	}
}

func TestCountryMarkGuardBuildPlatformAndPinnedAsset(t *testing.T) {
	wire, err := proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{Code: "RU", Cidr: []*geodata.CIDR{{Ip: []byte{77, 0, 0, 0}, Prefix: 8}}},
		{Code: "US", Cidr: []*geodata.CIDR{{Ip: []byte{8, 8, 8, 0}, Prefix: 24}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, "geoip.dat"), wire, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_LOCATION_ASSET", dir)
	digest := sha256.Sum256(wire)
	cfg := &conf.SocketConfig{Mark: 41014, CountryMarkGuard: &conf.CountryMarkGuardConfig{RuMark: 41060, NonRuMark: 41014, GeoIPFile: "geoip.dat", GeoIPSHA256: hex.EncodeToString(digest[:])}}
	built, err := cfg.Build()
	if runtime.GOOS != "linux" {
		if err == nil || !strings.Contains(err.Error(), "Linux") {
			t.Fatal("unsupported platform allowed guard")
		}
		return
	}
	if err != nil || built.GetCountryMarkGuard() == nil || built.GetCountryMarkGuard().GetRuMark() != 41060 || built.GetMark() != 41014 {
		t.Fatalf("guard lost during config build: %v", err)
	}
}
