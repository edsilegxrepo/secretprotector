//go:build windows

// Package libsecsecrets Windows key-file ownership stub.
// Windows enforces key-file security boundaries via path canonicalization and shared/temp directory blocking
// (validateWindowsKeyPath) rather than POSIX UID attributes.
package libsecsecrets

import "os"

// checkFileOwner is a no-op on Windows because POSIX UID ownership metadata is not applicable.
func checkFileOwner(_ os.FileInfo, _ func() int) error {
	return nil
}
