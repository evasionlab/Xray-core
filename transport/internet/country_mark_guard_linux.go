//go:build linux

package internet

import "syscall"

func setCountrySocketMark(fd uintptr, mark int32) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
}
