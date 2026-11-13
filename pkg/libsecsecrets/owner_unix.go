//go:build !windows

// Package libsecsecrets Unix key-file ownership verification helper.
package libsecsecrets

import (
	"fmt"
	"os"
	"syscall"
)

// checkFileOwner validates that the opened key file is owned by the current effective user on Unix systems.
//
// Objective:
// Prevent reading master key files owned by another local user even when mode bits appear restrictive.
//
// Enforcement:
// - Extracts *syscall.Stat_t from os.FileInfo.Sys() (allowing synthetic mocks when Sys() is nil).
// - Compares Stat_t.Uid against geteuid() and returns ErrInsecurePermissions on mismatch.
func checkFileOwner(info os.FileInfo, geteuid func() int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return nil
	}
	euid := geteuid()
	if euid >= 0 && int(stat.Uid) != euid {
		return fmt.Errorf("%w: file owner uid %d does not match effective uid %d", ErrInsecurePermissions, stat.Uid, euid)
	}
	return nil
}
