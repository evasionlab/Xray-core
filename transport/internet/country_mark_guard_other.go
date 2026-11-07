//go:build !linux

package internet

import "errors"

func setCountrySocketMark(uintptr, int32) error {
	return errors.New("country mark guard requires Linux SO_MARK")
}
