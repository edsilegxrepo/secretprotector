//go:build !windows

// Package libsecsecrets Unix key-file ownership unit tests.
//
// Objective:
// Validate that readProtectedKeyFile rejects key files whose Unix owner UID differs from the process effective UID
// while permitting files owned by the current effective user.
//
// Scenarios Covered:
// - Mismatched owner UID returning ErrInsecurePermissions.
// - Matching owner UID resolving a valid 32-byte key.
package libsecsecrets

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
)

// TestUnixFileOwnershipEnforcement validates Unix effective-UID enforcement on key files.
//
// Scenario:
// 1. Provide a mock stat UID differing from effective UID -> must fail with ErrInsecurePermissions.
// 2. Provide a matching mock stat UID and effective UID -> must resolve the 32-byte master key.
//
// Success Criteria:
// - UID mismatch fails fast with ErrInsecurePermissions.
// - Matching UID succeeds and decodes a 32-byte key.
func TestUnixFileOwnershipEnforcement(t *testing.T) {
	t.Parallel()
	keyHex := strings.Repeat("a", 64)

	makeDeps := func(uid uint32, euid int) sysDeps {
		return sysDeps{
			goos:    "linux",
			geteuid: func() int { return euid },
			openFile: func(name string) (fileHandle, error) {
				return &mockFileHandle{
					Reader: strings.NewReader(keyHex),
					info: &mockFileInfo{
						mode: 0o400,
						size: int64(len(keyHex)),
						sys:  &syscall.Stat_t{Uid: uid},
					},
				}, nil
			},
		}
	}

	// 1. Verify mismatched owner UID returns ErrInsecurePermissions.
	if _, err := makeDeps(99999, 1000).resolveKey(context.Background(), "", "", "/etc/secrets/master.key"); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("expected ErrInsecurePermissions for uid mismatch, got %v", err)
	}

	// 2. Verify matching owner UID resolves the 32-byte key cleanly.
	got, err := makeDeps(1000, 1000).resolveKey(context.Background(), "", "", "/etc/secrets/master.key")
	if err != nil {
		t.Fatalf("expected matching uid to succeed, got %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(got))
	}
}
