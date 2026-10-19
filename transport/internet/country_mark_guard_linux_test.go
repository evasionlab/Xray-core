//go:build linux

package internet

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// CI runs this compiled test binary under existing sudo capability, with the
// explicit proof variable. Default test execution does not claim kernel proof.
func TestLinuxKernelCountryMarkGuard(t *testing.T) {
	if os.Getenv("XRAY_COUNTRY_MARK_KERNEL_PROOF") != "1" {
		t.Skip("explicit privileged CI kernel proof required")
	}
	index, cfg := fixtureIndex(t)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "country-mark-qa-socket")
	defer file.Close()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		address string
		mark    int
	}{{"77.1.2.3:443", 41060}, {"8.8.8.8:443", 41014}} {
		err = countryMarkControl(index, cfg, "tcp4", tc.address, raw, func(fd uintptr) error {
			return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, 41014)
		}, setCountrySocketMark)
		if err != nil {
			t.Fatalf("actual kernel SO_MARK failed: %v", err)
		}
		mark, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK)
		if err != nil || mark != tc.mark {
			t.Fatalf("actual socket mark=%d want=%d err=%v", mark, tc.mark, err)
		}
		if _, err = syscall.Getpeername(fd); !errors.Is(err, syscall.ENOTCONN) {
			t.Fatal("QA socket unexpectedly connected")
		}
	}
	// A real kernel EBADF from SO_MARK must propagate through the inner callback.
	err = countryMarkControl(index, cfg, "tcp4", "8.8.8.8:443", raw, nil, func(uintptr, int32) error { return setCountrySocketMark(^uintptr(0), 41014) })
	if !errors.Is(err, syscall.EBADF) {
		t.Fatal("actual SO_MARK failure ignored")
	}
	file.Close()
	if err = countryMarkControl(index, cfg, "tcp4", "8.8.8.8:443", raw, nil, setCountrySocketMark); err == nil {
		t.Fatal("closed actual RawConn accepted")
	}
}
