// Package libsecsecrets provides unit tests for the libsecsecrets package.
// It verifies cryptographic integrity, key generation, key resolution precedence, platform security boundaries,
// and performance optimizations like sync.Pool reuse.
//
// Test Strategy:
// 1. Cryptographic Correctness:
//   - Round-trip (Encrypt/Decrypt, EncryptBytes/DecryptBytes, *WithAAD) verification for confidentiality and integrity.
//   - Validation of random key generation (GenerateKey, GenerateRawKey, GenerateKeyBytes) using CSPRNG.
//
// 2. Key Resolution Hierarchy:
//   - Isolated sysDeps and environment mocks to verify precedence: CLI Flag > Environment Variable > File.
//   - Verification of fallback mechanisms when higher-priority sources are absent or empty.
//
// 3. Platform Security Enforcement:
//   - Linux/Unix: Mocking single-open file handle attributes to enforce regular file, UID, special bits, and 0400/0600 modes.
//   - Windows: Path-segment and symlink/junction validation to block insecure locations (Public, Temp, tmp).
//
// 4. Error Resilience and Edge Cases:
//   - Testing failure modes for key generation and nonce creation (e.g., entropy exhaustion).
//   - Handling of malformed keys, unsupported version headers, short ciphertexts, and bounded read limits.
//   - Decryption failures (tampered ciphertext, incorrect keys, mismatched AAD, canceled/nil contexts).
//
// 5. Memory Safety and Resource Management:
//   - Verification of sync.Pool for buffer reuse to minimize GC overhead.
//   - Direct and implicit verification of ZeroBuffer scrubbing on keys and temporary buffers.
package libsecsecrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// mockFileInfo implements os.FileInfo for platform permission, size, and ownership unit tests.
type mockFileInfo struct {
	os.FileInfo
	mode os.FileMode
	size int64
	sys  any
}

func (m *mockFileInfo) Mode() os.FileMode { return m.mode }
func (m *mockFileInfo) Size() int64       { return m.size }
func (m *mockFileInfo) Sys() any          { return m.sys }

// mockFileHandle simulates an opened fileHandle (Reader + Closer + Stat) for single-open TOCTOU-safe tests.
type mockFileHandle struct {
	io.Reader
	info    os.FileInfo
	statErr error
}

func (m *mockFileHandle) Close() error               { return nil }
func (m *mockFileHandle) Stat() (os.FileInfo, error) { return m.info, m.statErr }

// errReader always returns the configured error on Read to test bounded I/O failure paths.
type errReader struct {
	err error
}

func (e errReader) Read(_ []byte) (int, error) { return 0, e.err }

// newTestDeps returns an isolated, race-free sysDeps baseline suitable for t.Parallel() unit tests.
func newTestDeps() sysDeps {
	return sysDeps{
		randReader:   rand.Reader,
		stdin:        func() io.Reader { return strings.NewReader("") },
		getenv:       func(string) string { return "" },
		tempDir:      func() string { return `C:\Users\Test\AppData\Local\Temp` },
		geteuid:      func() int { return 1000 },
		goos:         "linux",
		evalSymlinks: func(p string) (string, error) { return p, nil },
	}
}

// makeTempDirInWD returns t.TempDir() on Unix/Linux (ensuring native POSIX 0600 permissions)
// and creates a cleaned temporary directory under os.Getwd() on Windows so tests do not trigger %TEMP% / Local\Temp insecure-location blocks.
func makeTempDirInWD(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return t.TempDir()
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working dir: %v", err)
	}
	dir, err := os.MkdirTemp(wd, "sp_testkeys_")
	if err != nil {
		t.Fatalf("failed to create temp dir in wd: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

// TestGenerateKey verifies that the generated key is a valid 64-character hex string and exercises sync.Pool reuse.
func TestGenerateKey(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if len(key) != 64 {
		t.Errorf("Expected 64-char hex string, got %d", len(key))
	}
	if _, err := hex.DecodeString(key); err != nil {
		t.Errorf("Generated key is not valid hex: %v", err)
	}

	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("Subsequent GenerateKey failed: %v", err)
	}
	if len(key2) != 64 {
		t.Errorf("Expected 64-char hex string, got %d", len(key2))
	}
	if key == key2 {
		t.Errorf("Expected distinct random keys across calls")
	}
}

// TestGenerateRawKey verifies 32-char printable Base64URL key generation and round-trip compatibility.
func TestGenerateRawKey(t *testing.T) {
	t.Parallel()
	rawKey, err := GenerateRawKey()
	if err != nil {
		t.Fatalf("GenerateRawKey failed: %v", err)
	}
	if len(rawKey) != 32 {
		t.Fatalf("Expected 32-char Base64URL key, got %d (%q)", len(rawKey), rawKey)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(rawKey)
	if err != nil || len(decoded) != 24 {
		t.Fatalf("Expected valid 24-byte Base64URL payload, got len=%d err=%v", len(decoded), err)
	}

	resolved, err := ResolveKey(context.Background(), rawKey, "", "")
	if err != nil {
		t.Fatalf("ResolveKey failed for GenerateRawKey output: %v", err)
	}
	if !bytes.Equal(resolved, []byte(rawKey)) {
		t.Errorf("Resolved key mismatch: got %x, want %x", resolved, []byte(rawKey))
	}

	ct, err := Encrypt(context.Background(), "raw-key-secret", resolved)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	pt, err := Decrypt(context.Background(), ct, resolved)
	if err != nil || pt != "raw-key-secret" {
		t.Fatalf("Decrypt mismatch: got %q err=%v", pt, err)
	}
}

// TestGenerateKeyBytes verifies raw 32-byte key generation and entropy failure handling.
func TestGenerateKeyBytes(t *testing.T) {
	t.Parallel()
	b, err := GenerateKeyBytes()
	if err != nil {
		t.Fatalf("GenerateKeyBytes failed: %v", err)
	}
	defer ZeroBuffer(b)
	if len(b) != 32 {
		t.Fatalf("Expected 32 bytes, got %d", len(b))
	}

	d := newTestDeps()
	d.randReader = strings.NewReader("")
	if _, err := d.generateKeyBytes(); err == nil {
		t.Fatal("Expected error when entropy reader is empty")
	}
	if _, err := d.generateRawKey(); err == nil {
		t.Fatal("Expected error from generateRawKey when entropy reader is empty")
	}
}

// TestIsEncrypted verifies v1:gcm: prefix detection across valid, padded, bare, legacy, and plaintext inputs.
func TestIsEncrypted(t *testing.T) {
	t.Parallel()
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	ct, err := Encrypt(context.Background(), "hello", key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"ValidPrefixed", ct, true},
		{"WhitespacePadded", "  \n\t" + ct + " \r\n", true},
		{"BarePrefixOnly", EncryptedPrefix, false},
		{"LegacyRawBase64", strings.TrimPrefix(ct, EncryptedPrefix), false},
		{"Plaintext", "not-encrypted", false},
		{"Empty", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsEncrypted(tc.in); got != tc.want {
				t.Errorf("IsEncrypted(%q) = %v, want %v", tc.in, got, tc.want)
			}
			if got := IsEncryptedBytes([]byte(tc.in)); got != tc.want {
				t.Errorf("IsEncryptedBytes(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestEncryptDecrypt verifies the cryptographic round-trip, prefix format, empty inputs, and legacy Base64 support.
func TestEncryptDecrypt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	plaintext := "secret_password_123"

	encrypted, err := Encrypt(ctx, plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !strings.HasPrefix(encrypted, EncryptedPrefix) {
		t.Fatalf("Expected output to have prefix %q, got %q", EncryptedPrefix, encrypted)
	}

	decrypted, err := Decrypt(ctx, encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Decrypted text does not match plaintext: got %q, want %q", decrypted, plaintext)
	}

	// Backwards-compatible legacy unprefixed Base64 decryption
	legacy := strings.TrimPrefix(encrypted, EncryptedPrefix)
	decryptedLegacy, err := Decrypt(ctx, legacy, key)
	if err != nil || decryptedLegacy != plaintext {
		t.Errorf("Legacy unprefixed Decrypt failed: got %q err=%v", decryptedLegacy, err)
	}

	// Empty plaintext round-trip
	encEmpty, err := Encrypt(ctx, "", key)
	if err != nil {
		t.Fatalf("Encrypt empty string failed: %v", err)
	}
	decEmpty, err := Decrypt(ctx, encEmpty, key)
	if err != nil || decEmpty != "" {
		t.Errorf("Decrypt empty string failed: got %q err=%v", decEmpty, err)
	}
}

// TestEncryptDecryptBytes verifies byte-slice cryptographic round-trip and whitespace trimming.
func TestEncryptDecryptBytes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	plainBytes := []byte("binary_secret_data_456")

	encryptedBytes, err := EncryptBytes(ctx, plainBytes, key)
	if err != nil {
		t.Fatalf("EncryptBytes failed: %v", err)
	}

	paddedEncrypted := append([]byte(" \r\n "), append(encryptedBytes, []byte(" \n\r ")...)...)
	decryptedBytes, err := DecryptBytes(ctx, paddedEncrypted, key)
	if err != nil {
		t.Fatalf("DecryptBytes failed on padded input: %v", err)
	}
	if !bytes.Equal(decryptedBytes, plainBytes) {
		t.Errorf("Decrypted bytes do not match plaintext: got %q, want %q", decryptedBytes, plainBytes)
	}

	// Empty byte slice round-trip
	encEmpty, err := EncryptBytes(ctx, []byte{}, key)
	if err != nil {
		t.Fatalf("EncryptBytes empty failed: %v", err)
	}
	decEmpty, err := DecryptBytes(ctx, encEmpty, key)
	if err != nil || len(decEmpty) != 0 {
		t.Errorf("DecryptBytes empty failed: got %q err=%v", decEmpty, err)
	}
}

// TestEncryptDecryptWithAAD verifies AAD binding prevents cross-context ciphertext substitution.
func TestEncryptDecryptWithAAD(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	aad := []byte("sftp.example.com:password")

	ct, err := EncryptWithAAD(ctx, "db-secret", key, aad)
	if err != nil {
		t.Fatalf("EncryptWithAAD failed: %v", err)
	}

	pt, err := DecryptWithAAD(ctx, ct, key, aad)
	if err != nil || pt != "db-secret" {
		t.Fatalf("DecryptWithAAD with matching AAD failed: got %q err=%v", pt, err)
	}

	if _, err := DecryptWithAAD(ctx, ct, key, []byte("wrong-context")); err == nil {
		t.Fatal("Expected DecryptWithAAD to fail with mismatched AAD")
	}
	if _, err := Decrypt(ctx, ct, key); err == nil {
		t.Fatal("Expected Decrypt without AAD to fail for AAD-protected ciphertext")
	}

	ctBytes, err := EncryptBytesWithAAD(ctx, []byte("bytes-secret"), key, aad)
	if err != nil {
		t.Fatalf("EncryptBytesWithAAD failed: %v", err)
	}
	ptBytes, err := DecryptBytesWithAAD(ctx, ctBytes, key, aad)
	if err != nil || string(ptBytes) != "bytes-secret" {
		t.Fatalf("DecryptBytesWithAAD failed: got %q err=%v", ptBytes, err)
	}
	if _, err := DecryptBytesWithAAD(ctx, ctBytes, key, []byte("other")); err == nil {
		t.Fatal("Expected DecryptBytesWithAAD to fail with wrong AAD")
	}
}

// TestZeroBuffer verifies that ZeroBuffer overwrites all slice bytes with zero.
func TestZeroBuffer(t *testing.T) {
	t.Parallel()
	buf := []byte("super-sensitive-master-key-bytes")
	ZeroBuffer(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("Expected byte %d to be 0 after ZeroBuffer, got %d", i, b)
		}
	}
}

// TestResolveKeyPrecedence verifies Flag > Env > File hierarchy and empty env fallback.
func TestResolveKeyPrecedence(t *testing.T) {
	ctx := context.Background()
	dir := makeTempDirInWD(t)
	keyFile := filepath.Join(dir, "key.txt")

	rawKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	envKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	fileKey := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	if err := os.WriteFile(keyFile, []byte(fileKey), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	t.Setenv("TEST_MASTER_KEY", envKey)
	t.Setenv("EMPTY_ENV", "")

	// 1. Raw overrides Env and File
	resolved, err := ResolveKey(ctx, rawKey, "TEST_MASTER_KEY", keyFile)
	if err != nil {
		t.Fatalf("ResolveKey raw failed: %v", err)
	}
	if hex.EncodeToString(resolved) != rawKey {
		t.Errorf("Raw key precedence failed: got %x, want %s", resolved, rawKey)
	}

	// 2. Env overrides File
	resolved, err = ResolveKey(ctx, "", "TEST_MASTER_KEY", keyFile)
	if err != nil {
		t.Fatalf("ResolveKey env failed: %v", err)
	}
	if hex.EncodeToString(resolved) != envKey {
		t.Errorf("Env key precedence failed: got %x, want %s", resolved, envKey)
	}

	// 3. File fallback
	resolved, err = ResolveKey(ctx, "", "", keyFile)
	if err != nil {
		t.Fatalf("ResolveKey file failed: %v", err)
	}
	if hex.EncodeToString(resolved) != fileKey {
		t.Errorf("File key fallback failed: got %x, want %s", resolved, fileKey)
	}

	// 4. Empty env falls back to File
	resolved, err = ResolveKey(ctx, "", "EMPTY_ENV", keyFile)
	if err != nil {
		t.Fatalf("ResolveKey empty env fallback failed: %v", err)
	}
	if hex.EncodeToString(resolved) != fileKey {
		t.Errorf("Empty env fallback failed: got %x, want %s", resolved, fileKey)
	}
}

// TestResolveKeyFileVariants verifies hex, raw, line-ending, and space-handling behavior for key files.
func TestResolveKeyFileVariants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	testDir := makeTempDirInWD(t)

	// 1. 64-char hex key
	hexKey := strings.Repeat("a", 64)
	hexFile := filepath.Join(testDir, "hex.txt")
	if err := os.WriteFile(hexFile, []byte(hexKey), 0o600); err != nil {
		t.Fatalf("failed to write hex file: %v", err)
	}
	resolved, err := ResolveKey(ctx, "", "", hexFile)
	if err != nil || hex.EncodeToString(resolved) != hexKey {
		t.Fatalf("hex file failed: got %x err=%v", resolved, err)
	}

	// 2. 32-byte raw key
	rawKey := strings.Repeat("r", 32)
	rawFile := filepath.Join(testDir, "raw.txt")
	if err := os.WriteFile(rawFile, []byte(rawKey), 0o600); err != nil {
		t.Fatalf("failed to write raw file: %v", err)
	}
	resolved, err = ResolveKey(ctx, "", "", rawFile)
	if err != nil || string(resolved) != rawKey {
		t.Fatalf("raw file failed: got %q err=%v", resolved, err)
	}

	// 3. 32-byte raw key with leading 0x20 byte
	leadingSpaceKey, _ := hex.DecodeString("2006a25c6760dc2da911ea11464b57bfb762e95b958fc31b5266660f5646c919")
	leadingSpaceFile := filepath.Join(testDir, "raw-leading-space.bin")
	if err := os.WriteFile(leadingSpaceFile, leadingSpaceKey, 0o600); err != nil {
		t.Fatalf("failed to write leading-space raw file: %v", err)
	}
	resolved, err = ResolveKey(ctx, "", "", leadingSpaceFile)
	if err != nil || !bytes.Equal(resolved, leadingSpaceKey) {
		t.Fatalf("leading-space raw file failed: got %x err=%v", resolved, err)
	}

	// 4. 32-byte raw key with trailing 0x20 byte
	trailingSpaceKey := append(bytes.Repeat([]byte{0x42}, 31), 0x20)
	trailingSpaceFile := filepath.Join(testDir, "raw-trailing-space.bin")
	if err := os.WriteFile(trailingSpaceFile, trailingSpaceKey, 0o600); err != nil {
		t.Fatalf("failed to write trailing-space raw file: %v", err)
	}
	resolved, err = ResolveKey(ctx, "", "", trailingSpaceFile)
	if err != nil || !bytes.Equal(resolved, trailingSpaceKey) {
		t.Fatalf("trailing-space raw file failed: got %x err=%v", resolved, err)
	}

	// 5. 64-char hex key with trailing newline
	hexWithNewlineFile := filepath.Join(testDir, "hex-newline.txt")
	if err := os.WriteFile(hexWithNewlineFile, []byte(hexKey+"\n"), 0o600); err != nil {
		t.Fatalf("failed to write hex newline file: %v", err)
	}
	resolved, err = ResolveKey(ctx, "", "", hexWithNewlineFile)
	if err != nil || hex.EncodeToString(resolved) != hexKey {
		t.Fatalf("hex newline file failed: got %x err=%v", resolved, err)
	}

	// 6. 32-char GenerateRawKey saved with CRLF
	genRaw, err := GenerateRawKey()
	if err != nil {
		t.Fatalf("GenerateRawKey failed: %v", err)
	}
	rawCRLFFile := filepath.Join(testDir, "raw-crlf.txt")
	if err := os.WriteFile(rawCRLFFile, []byte(genRaw+"\r\n"), 0o600); err != nil {
		t.Fatalf("failed to write raw crlf file: %v", err)
	}
	resolved, err = ResolveKey(ctx, "", "", rawCRLFFile)
	if err != nil || string(resolved) != genRaw {
		t.Fatalf("raw crlf file failed: got %q err=%v", resolved, err)
	}

	// 7. Corrupted 34-byte binary file ending in spaces must NOT silently truncate to 32 bytes
	corrupted := append(bytes.Repeat([]byte{0x41}, 32), 0x20, 0x20)
	corruptedFile := filepath.Join(testDir, "corrupted-34.bin")
	if err := os.WriteFile(corruptedFile, corrupted, 0o600); err != nil {
		t.Fatalf("failed to write corrupted file: %v", err)
	}
	if _, err := ResolveKey(ctx, "", "", corruptedFile); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for 34-byte space-padded file, got %v", err)
	}

	// 8. Corrupted 33-byte binary file ending in standalone CR (\r) must NOT silently truncate to 32 bytes
	corruptedCR := append(bytes.Repeat([]byte{0x41}, 32), '\r')
	corruptedCRFile := filepath.Join(testDir, "corrupted-33-cr.bin")
	if err := os.WriteFile(corruptedCRFile, corruptedCR, 0o600); err != nil {
		t.Fatalf("failed to write corrupted CR file: %v", err)
	}
	if _, err := ResolveKey(ctx, "", "", corruptedCRFile); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for 33-byte standalone-CR file, got %v", err)
	}

	// 9. Corrupted 33-byte/34-byte binary files containing non-printable bytes and ending in \n or \r\n
	// must NOT silently truncate to 32 bytes, while exact 32-byte binary keys with \x00/\n remain valid.
	exactBinary32 := append(bytes.Repeat([]byte{0x00, 0x0a}, 15), 0xff, 0x1b)
	exactBinaryFile := filepath.Join(testDir, "exact-32-binary.bin")
	if err := os.WriteFile(exactBinaryFile, exactBinary32, 0o600); err != nil {
		t.Fatalf("failed to write exact 32-byte binary file: %v", err)
	}
	resolved, err = ResolveKey(ctx, "", "", exactBinaryFile)
	if err != nil || !bytes.Equal(resolved, exactBinary32) {
		t.Fatalf("exact 32-byte binary file failed: got %x err=%v", resolved, err)
	}

	corruptedLF := append(append(bytes.Repeat([]byte{0x41}, 31), 0x00), '\n')
	corruptedLFFile := filepath.Join(testDir, "corrupted-33-lf.bin")
	if err := os.WriteFile(corruptedLFFile, corruptedLF, 0o600); err != nil {
		t.Fatalf("failed to write corrupted LF binary file: %v", err)
	}
	if _, err := ResolveKey(ctx, "", "", corruptedLFFile); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for 33-byte binary file ending in LF, got %v", err)
	}

	corruptedCRLF := append(append(bytes.Repeat([]byte{0x41}, 31), 0x80), '\r', '\n')
	corruptedCRLFFile := filepath.Join(testDir, "corrupted-34-crlf.bin")
	if err := os.WriteFile(corruptedCRLFFile, corruptedCRLF, 0o600); err != nil {
		t.Fatalf("failed to write corrupted CRLF binary file: %v", err)
	}
	if _, err := ResolveKey(ctx, "", "", corruptedCRLFFile); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for 34-byte binary file ending in CRLF, got %v", err)
	}
}

// TestPlatformFileSecurity verifies Windows path-boundary/symlink validation and Unix file mode/type checks.
func TestPlatformFileSecurity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	validHex := strings.Repeat("c", 64)

	openMockFile := func(mode os.FileMode) func(string) (fileHandle, error) {
		return func(name string) (fileHandle, error) {
			return &mockFileHandle{
				Reader: strings.NewReader(validHex),
				info:   &mockFileInfo{mode: mode, size: int64(len(validHex))},
			}, nil
		}
	}

	t.Run("WindowsLocations", func(t *testing.T) {
		t.Parallel()
		winDeps := newTestDeps()
		winDeps.goos = "windows"
		winDeps.openFile = openMockFile(0o600)

		blocked := []string{
			`C:\Users\Public\key.txt`,
			`C:\Windows\Temp\key.txt`,
			`C:\Temp\key.txt`,
			`C:\tmp\key.txt`,
			`\\?\C:\Users\Public\key.txt`,
			`\\?\UNC\server\share\temp\key.txt`,
			`\\.\C:\Temp\key.txt`,
			`C:\Users\Test\AppData\Local\Temp\key.txt`,
		}
		for _, p := range blocked {
			if _, err := winDeps.resolveKey(ctx, "", "", p); !errors.Is(err, ErrInsecureLocation) {
				t.Errorf("expected ErrInsecureLocation for %q, got %v", p, err)
			}
		}

		// Symlink/junction resolving into Public must be blocked
		junctionDeps := winDeps
		junctionDeps.evalSymlinks = func(p string) (string, error) {
			if strings.Contains(p, "SafeLink") {
				return `C:\Users\Public\key.txt`, nil
			}
			return p, nil
		}
		if _, err := junctionDeps.resolveKey(ctx, "", "", `C:\SafeLink\key.txt`); !errors.Is(err, ErrInsecureLocation) {
			t.Errorf("expected ErrInsecureLocation for symlink/junction into Public, got %v", err)
		}

		// Symlink evaluation errors must fail closed with ErrInsecureLocation
		evalErrDeps := winDeps
		evalErrDeps.evalSymlinks = func(string) (string, error) {
			return "", errors.New("broken reparse point")
		}
		if _, err := evalErrDeps.resolveKey(ctx, "", "", `C:\ProgramData\MyApp\master.key`); !errors.Is(err, ErrInsecureLocation) {
			t.Errorf("expected ErrInsecureLocation on evalSymlinks error, got %v", err)
		}

		// Valid paths sharing prefix characters with blocked names or safe UNC paths must NOT false-positive
		allowed := []string{
			`C:\Users\PublicAdmin\key.txt`,
			`C:\Template\key.txt`,
			`C:\ProgramData\MyApp\master.key`,
			`\\?\UNC\server\share\secrets\master.key`,
		}
		for _, p := range allowed {
			if _, err := winDeps.resolveKey(ctx, "", "", p); err != nil {
				t.Errorf("expected %q to be allowed, got %v", p, err)
			}
		}
	})

	t.Run("UnixPermissionsAndFileTypes", func(t *testing.T) {
		t.Parallel()
		badModes := []os.FileMode{
			0o644,
			0o640,
			0o700,
			os.ModeNamedPipe | 0o600,
			os.ModeDir | 0o600,
			os.ModeSetuid | 0o600,
			os.ModeSticky | 0o600,
		}
		for _, mode := range badModes {
			d := newTestDeps()
			d.goos = "linux"
			d.openFile = openMockFile(mode)
			if _, err := d.resolveKey(ctx, "", "", "/etc/secrets/key.txt"); !errors.Is(err, ErrInsecurePermissions) {
				t.Errorf("expected ErrInsecurePermissions for mode %v, got %v", mode, err)
			}
		}

		for _, goodMode := range []os.FileMode{0o400, 0o600} {
			d := newTestDeps()
			d.goos = "linux"
			d.openFile = openMockFile(goodMode)
			if _, err := d.resolveKey(ctx, "", "", "/etc/secrets/key.txt"); err != nil {
				t.Errorf("expected mode %o to succeed, got %v", goodMode, err)
			}
		}
	})
}

// TestErrorsAndEdgeCases verifies error paths, bounded reads, context handling, and version checks.
func TestErrorsAndEdgeCases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	// 1. Entropy exhaustion via isolated sysDeps
	noRand := newTestDeps()
	noRand.randReader = strings.NewReader("")
	if _, err := noRand.generateKey(); err == nil {
		t.Error("expected GenerateKey error with empty randReader")
	}
	if _, err := noRand.encryptBytesWithAAD(ctx, []byte("plain"), key, nil); err == nil {
		t.Error("expected encrypt error with empty randReader")
	}

	// 2. Invalid key lengths
	if _, err := Encrypt(ctx, "plain", []byte("short")); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey from Encrypt, got %v", err)
	}
	if _, err := EncryptBytes(ctx, []byte("plain"), []byte("short")); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey from EncryptBytes, got %v", err)
	}
	if _, err := DecryptBytes(ctx, []byte("encoded"), []byte("short")); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey from DecryptBytes, got %v", err)
	}
	if _, err := Decrypt(ctx, base64.StdEncoding.EncodeToString(make([]byte, 32)), []byte("short")); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey from Decrypt, got %v", err)
	}

	// 3. Ciphertext decoding, minimum length, unsupported version, wrong key
	if _, err := Decrypt(ctx, "invalid-base64!", key); err == nil {
		t.Error("expected error for invalid base64")
	}
	if _, err := Decrypt(ctx, EncryptedPrefix, key); !errors.Is(err, ErrCiphertextTooShort) {
		t.Errorf("expected ErrCiphertextTooShort for bare prefix, got %v", err)
	}
	if _, err := Decrypt(ctx, base64.StdEncoding.EncodeToString(make([]byte, 20)), key); !errors.Is(err, ErrCiphertextTooShort) {
		t.Errorf("expected ErrCiphertextTooShort for 20-byte payload (<28), got %v", err)
	}
	if _, err := Decrypt(ctx, "v2:gcm:AAAA", key); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("expected ErrUnsupportedVersion for v2:gcm:, got %v", err)
	}
	if _, err := Decrypt(ctx, "v2:xchacha20:AAAA", key); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("expected ErrUnsupportedVersion for v2:xchacha20:, got %v", err)
	}

	wrongKey, _ := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	encrypted, _ := Encrypt(ctx, "secret", key)
	if _, err := Decrypt(ctx, encrypted, wrongKey); err == nil {
		t.Error("expected decryption failure with wrong key")
	}

	// 4. ResolveKey validation errors
	if _, err := ResolveKey(ctx, "", "", ""); !errors.Is(err, ErrNoKeySource) {
		t.Errorf("expected ErrNoKeySource, got %v", err)
	}
	if _, err := ResolveKey(ctx, "invalid-hex", "", ""); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
	if _, err := ResolveKey(ctx, strings.Repeat("z", 64), "", ""); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey for 64-char non-hex, got %v", err)
	}
	if _, err := ResolveKey(ctx, hex.EncodeToString(make([]byte, 15)), "", ""); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey for 30-char hex, got %v", err)
	}

	// 5. Context cancellation and nil context safety
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ResolveKey(canceledCtx, strings.Repeat("a", 64), "", ""); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled from ResolveKey, got %v", err)
	}
	if _, err := EncryptBytes(canceledCtx, []byte("a"), key); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled from EncryptBytes, got %v", err)
	}
	if _, err := DecryptBytes(canceledCtx, []byte(encrypted), key); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled from DecryptBytes, got %v", err)
	}

	deadlineCtx, deadlineCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer deadlineCancel()
	if _, err := ResolveKey(deadlineCtx, strings.Repeat("a", 64), "", ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}

	// nil context must not panic
	//nolint:staticcheck // intentionally testing nil context safety
	if _, err := EncryptBytes(nil, []byte("ok"), key); err != nil {
		t.Errorf("nil context EncryptBytes failed: %v", err)
	}

	// 6. Bounded read checks (file stat size, streaming size, stdin size)
	oversizedStatDeps := newTestDeps()
	oversizedStatDeps.openFile = func(name string) (fileHandle, error) {
		return &mockFileHandle{
			Reader: strings.NewReader("ignored"),
			info:   &mockFileInfo{mode: 0o600, size: maxKeyInputBytes + 1},
		}, nil
	}
	if _, err := oversizedStatDeps.resolveKey(ctx, "", "", "/etc/secrets/huge.key"); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey for oversized file stat, got %v", err)
	}

	oversizedStreamDeps := newTestDeps()
	oversizedStreamDeps.openFile = func(name string) (fileHandle, error) {
		return &mockFileHandle{
			Reader: strings.NewReader(strings.Repeat("a", maxKeyInputBytes+10)),
			info:   &mockFileInfo{mode: 0o600, size: 64},
		}, nil
	}
	if _, err := oversizedStreamDeps.resolveKey(ctx, "", "", "/etc/secrets/stream.key"); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey for oversized file stream, got %v", err)
	}

	oversizedStdinDeps := newTestDeps()
	oversizedStdinDeps.stdin = func() io.Reader {
		return strings.NewReader(strings.Repeat("a", maxKeyInputBytes+10))
	}
	if _, err := oversizedStdinDeps.resolveKey(ctx, "", "", "-"); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey for oversized stdin key, got %v", err)
	}

	// 7. File Open / Stat / Read I/O errors
	openErrDeps := newTestDeps()
	openErrDeps.openFile = func(string) (fileHandle, error) {
		return nil, errors.New("open error")
	}
	if _, err := openErrDeps.resolveKey(ctx, "", "", "/etc/secrets/missing.key"); err == nil {
		t.Error("expected open error")
	}

	statErrDeps := newTestDeps()
	statErrDeps.openFile = func(string) (fileHandle, error) {
		return &mockFileHandle{statErr: errors.New("stat error")}, nil
	}
	if _, err := statErrDeps.resolveKey(ctx, "", "", "/etc/secrets/stat.key"); err == nil {
		t.Error("expected stat error")
	}

	readErrDeps := newTestDeps()
	readErrDeps.openFile = func(string) (fileHandle, error) {
		return &mockFileHandle{
			Reader: errReader{err: errors.New("read error")},
			info:   &mockFileInfo{mode: 0o600, size: 64},
		}, nil
	}
	if _, err := readErrDeps.resolveKey(ctx, "", "", "/etc/secrets/read.key"); err == nil {
		t.Error("expected read error")
	}
}

// TestResolveKeyStdin verifies key resolution from stdin via injected deps and real os.Stdin pipe.
func TestResolveKeyStdin(t *testing.T) {
	ctx := context.Background()
	key := strings.Repeat("a", 64)

	// 1. Injected stdin reader
	d := newTestDeps()
	d.stdin = func() io.Reader { return strings.NewReader(key + "\n") }
	resolved, err := d.resolveKey(ctx, "", "", "-")
	if err != nil || hex.EncodeToString(resolved) != key {
		t.Fatalf("injected stdin resolve failed: got %x err=%v", resolved, err)
	}

	// 2. Real os.Stdin pipe via public ResolveKey
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	go func() {
		_, _ = w.WriteString(key + "\n")
		_ = w.Close()
	}()
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = r.Close()
	})

	resolved, err = ResolveKey(ctx, "", "", "-")
	if err != nil {
		t.Fatalf("ResolveKey from os.Stdin failed: %v", err)
	}
	if hex.EncodeToString(resolved) != key {
		t.Errorf("Expected resolved key %s, got %x", key, resolved)
	}
}
