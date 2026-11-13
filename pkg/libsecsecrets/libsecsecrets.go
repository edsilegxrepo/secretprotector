// Package libsecsecrets provides a professional-grade implementation for password obfuscation in Go.
// It implements AES-256-GCM authenticated encryption and a multi-source master key resolution strategy.
//
// Objective:
// To ensure that sensitive credentials (such as SFTP passwords, API keys, or DB credentials)
// are never stored in plaintext on disk or in version control by using standardized
// cryptographic methods and secure key handling.
//
// Core Components:
// 1. Key Resolution: Hierarchical search (Flag > Env > File) with platform security enforcement.
// 2. Cryptography: AES-256-GCM providing confidentiality and integrity (with optional AAD).
// 3. Memory Safety: Utilities for zeroing sensitive buffers to minimize exposure.
// 4. Resource Optimization: sync.Pool for efficient buffer management.
//
// Data Flow:
// 1. Key Generation: CSPRNG -> 32-byte key (64-char hex, 32-char Base64URL, or raw bytes).
// 2. Key Resolution: Input (Raw/Env/File) -> Validation -> 32-byte key.
// 3. Encryption: Plaintext + Key (+ optional AAD) -> AES-GCM (Nonce + Seal) -> v1:gcm: Base64.
// 4. Decryption: Base64 + Key (+ optional AAD) -> Base64 Decode -> AES-GCM (Open) -> Plaintext.
package libsecsecrets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const (
	// DefaultKeyEnv is the default environment variable name used to store the master key.
	DefaultKeyEnv = "SECRETPROTECTOR_MASTER_KEY"

	// EncryptedPrefix is the version/algorithm prefix for encrypted values.
	// Format: v1:gcm:<base64-ciphertext>
	// - v1: Version identifier for future algorithm upgrades
	// - gcm: Algorithm identifier (AES-256-GCM)
	EncryptedPrefix = "v1:gcm:"

	// maxKeyInputBytes caps key file and stdin reads to prevent unbounded allocation.
	maxKeyInputBytes = 4096
)

// bytePool is a sync.Pool for reducing GC pressure on 32-byte key generation buffers.
var bytePool = sync.Pool{
	New: func() any {
		b := make([]byte, 32)
		return &b
	},
}

var (
	// ErrInvalidKey is returned when the provided key is not a valid 64-char hex string or 32-byte raw key.
	ErrInvalidKey = errors.New("invalid key: expected 64-char hex or 32-byte raw string")
	// ErrNoKeySource is returned when no master key could be resolved from any source.
	ErrNoKeySource = errors.New("no master key found in provided sources")
	// ErrInsecureLocation is returned when a key file is stored in an insecure location.
	ErrInsecureLocation = errors.New("insecure key location detected")
	// ErrInsecurePermissions is returned when a key file has unsafe permissions or file type.
	ErrInsecurePermissions = errors.New("insecure file permissions")
	// ErrCiphertextTooShort is returned when the data to decrypt is shorter than the AES-GCM nonce and tag.
	ErrCiphertextTooShort = errors.New("ciphertext too short")
	// ErrUnsupportedVersion is returned when ciphertext uses an unrecognized version/algorithm header.
	ErrUnsupportedVersion = errors.New("unsupported ciphertext version or algorithm")
)

// ZeroBuffer fills the provided byte slice with zeros to clear sensitive data from memory.
// This is used to minimize the window of exposure for sensitive material in RAM.
func ZeroBuffer(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

// fileHandle abstracts an opened key file so it can be stat-checked and read from the same OS handle.
type fileHandle interface {
	io.Reader
	io.Closer
	Stat() (os.FileInfo, error)
}

// sysDeps holds unexported OS, entropy, and I/O dependencies so tests can inject isolated doubles
// without mutating package-level global state.
type sysDeps struct {
	randReader   io.Reader
	stdin        func() io.Reader
	getenv       func(string) string
	tempDir      func() string
	geteuid      func() int
	goos         string
	openFile     func(string) (fileHandle, error)
	evalSymlinks func(string) (string, error)
}

// defaultDeps wires production OS and crypto/rand implementations for exported package functions.
var defaultDeps = sysDeps{
	randReader: rand.Reader,
	stdin:      func() io.Reader { return os.Stdin },
	getenv:     os.Getenv,
	tempDir:    os.TempDir,
	geteuid:    os.Geteuid,
	goos:       runtime.GOOS,
	openFile: func(name string) (fileHandle, error) {
		return os.Open(filepath.Clean(name)) // #nosec G304 -- caller explicitly configures key file path
	},
	evalSymlinks: filepath.EvalSymlinks,
}

// IsEncrypted checks if a string has the v1:gcm: encrypted prefix (ignoring surrounding whitespace).
func IsEncrypted(s string) bool {
	trimmed := strings.TrimSpace(s)
	return len(trimmed) > len(EncryptedPrefix) && strings.HasPrefix(trimmed, EncryptedPrefix)
}

// IsEncryptedBytes checks if a byte slice has the v1:gcm: encrypted prefix (ignoring surrounding whitespace).
func IsEncryptedBytes(b []byte) bool {
	trimmed := bytes.TrimSpace(b)
	return len(trimmed) > len(EncryptedPrefix) && bytes.HasPrefix(trimmed, []byte(EncryptedPrefix))
}

// hasVersionPrefix detects headers matching v<digits>:<alg>: (such as v2:gcm:).
// Colon is not a valid standard Base64 character, so legacy raw Base64 inputs never match.
func hasVersionPrefix(b []byte) bool {
	if len(b) < 5 || b[0] != 'v' {
		return false
	}
	i := 1
	digits := 0
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		digits++
		i++
	}
	if digits == 0 || i >= len(b) || b[i] != ':' {
		return false
	}
	i++
	algChars := 0
	for i < len(b) && ((b[i] >= 'a' && b[i] <= 'z') || (b[i] >= 'A' && b[i] <= 'Z') || (b[i] >= '0' && b[i] <= '9') || b[i] == '_' || b[i] == '-') {
		algChars++
		i++
	}
	return algChars > 0 && i < len(b) && b[i] == ':'
}

// GenerateKeyBytes generates 32 cryptographically secure random bytes using crypto/rand.
// Callers are responsible for calling ZeroBuffer on the returned slice after use.
//
// Data Flow:
// 1. Allocate a 32-byte slice.
// 2. Populate with random bytes from the configured CSPRNG reader.
// 3. Zero and discard on read failure; otherwise return the raw 32-byte key.
func GenerateKeyBytes() ([]byte, error) {
	return defaultDeps.generateKeyBytes()
}

// generateKeyBytes reads 32 CSPRNG bytes from sysDeps.randReader, scrubbing the slice if filling fails.
func (d sysDeps) generateKeyBytes() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(d.randReader, key); err != nil {
		ZeroBuffer(key)
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}

// GenerateKey returns a 64-character hex string representing 32 bytes of entropy.
// It uses crypto/rand for cryptographically secure random number generation.
//
// Data Flow:
// 1. Acquire a pooled 32-byte buffer from bytePool (and scrub before returning it to the pool).
// 2. Populate with random bytes from CSPRNG.
// 3. Return as a 64-character hex-encoded string.
func GenerateKey() (string, error) {
	return defaultDeps.generateKey()
}

// generateKey creates a 64-char hex master key using bytePool and sysDeps.randReader.
func (d sysDeps) generateKey() (string, error) {
	keyPtr := bytePool.Get().(*[]byte)
	key := *keyPtr
	defer func() {
		ZeroBuffer(key)
		bytePool.Put(keyPtr)
	}()

	if _, err := io.ReadFull(d.randReader, key); err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}
	return hex.EncodeToString(key), nil
}

// GenerateRawKey returns a 32-character printable Base64URL CSPRNG key (24 random bytes, 192 bits of entropy).
// It is safe for storage in both environment variables and key files while matching the 32-byte raw key format.
//
// Data Flow:
// 1. Allocate a stack-local 24-byte buffer and defer ZeroBuffer scrubbing.
// 2. Populate with random bytes from CSPRNG.
// 3. Encode with unpadded Base64URL (32 printable ASCII characters).
func GenerateRawKey() (string, error) {
	return defaultDeps.generateRawKey()
}

// generateRawKey creates a 32-char printable Base64URL key using sysDeps.randReader.
func (d sysDeps) generateRawKey() (string, error) {
	var raw [24]byte
	defer ZeroBuffer(raw[:])

	if _, err := io.ReadFull(d.randReader, raw[:]); err != nil {
		return "", fmt.Errorf("failed to generate random raw key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// ResolveKey finds and validates the master key from three possible sources in order of precedence:
// 1. raw: A direct 64-char hex or 32-byte raw key passed as an argument (Highest precedence).
// 2. env: An environment variable name containing the master key.
// 3. file: A path to a file (or "-" for stdin) containing the master key (Lowest precedence).
//
// Data Flow:
// 1. Verify context has not already been canceled or timed out (when non-nil).
// 2. Check if 'raw' (CLI flag) is provided; scrub temporary copy and validate format.
// 3. If not, lookup the environment variable specified by 'env'.
// 4. If still not found, read from stdin ("-") or bounded protected file ('file') after security checks.
// 5. Validate the resulting key bytes (64-char hex or 32-byte raw) and return a decoded 32-byte master key.
//
// Security Checks:
// - On Linux/Unix, it opens the key file once and enforces regular-file type, owner UID, no special bits, and 0400/0600 permissions.
// - On Windows, it resolves symlinks/junctions and blocks insecure locations such as Public or Temp directories.
func ResolveKey(ctx context.Context, raw, env, file string) ([]byte, error) {
	return defaultDeps.resolveKey(ctx, raw, env, file)
}

// resolveKey implements ResolveKey against injected sysDeps for lock-free concurrency and isolated tests.
func (d sysDeps) resolveKey(ctx context.Context, raw, env, file string) ([]byte, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	// Step 1: Direct raw key override.
	if raw != "" {
		rawBytes := []byte(raw)
		defer ZeroBuffer(rawBytes)
		return parseKeyBytes(rawBytes, "chars")
	}

	// Step 2: Environment variable resolution.
	if env != "" {
		if envVal := d.getenv(env); envVal != "" {
			envBytes := []byte(envVal)
			defer ZeroBuffer(envBytes)
			return parseKeyBytes(envBytes, "chars")
		}
	}

	// Step 3: File or stdin resolution.
	if file != "" {
		var keyData []byte
		var err error
		if file == "-" {
			keyData, err = readBounded(d.stdin(), maxKeyInputBytes)
			defer ZeroBuffer(keyData)
			if err != nil {
				if errors.Is(err, errInputTooLarge) {
					return nil, fmt.Errorf("%w: key input exceeds %d bytes", ErrInvalidKey, maxKeyInputBytes)
				}
				return nil, fmt.Errorf("failed to read key file from stdin: %w", err)
			}
		} else {
			keyData, err = d.readProtectedKeyFile(ctx, file)
			defer ZeroBuffer(keyData)
			if err != nil {
				return nil, err
			}
		}
		return parseKeyBytes(keyData, "bytes")
	}

	return nil, ErrNoKeySource
}

// errInputTooLarge signals that a stream or key file exceeded the configured read cap.
var errInputTooLarge = errors.New("input exceeds maximum allowed size")

// readBounded reads at most limit bytes from r, failing with errInputTooLarge (and scrubbing partial data) if exceeded.
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		ZeroBuffer(data)
		return nil, err
	}
	if int64(len(data)) > limit {
		ZeroBuffer(data)
		return nil, errInputTooLarge
	}
	return data, nil
}

// parseKeyBytes validates and decodes key material (direct flag, environment variable, file, or stdin).
// Exact 32-byte raw keys are preserved intact before attempting hex or trailing line-ending text checks.
func parseKeyBytes(data []byte, unit string) ([]byte, error) {
	// Exact 32-byte raw binary keys must be checked before any trimming.
	if len(data) == 32 {
		key := make([]byte, 32)
		copy(key, data)
		return key, nil
	}

	hexCandidate := bytes.TrimSpace(data)
	if len(hexCandidate) == 64 {
		key := make([]byte, 32)
		if _, err := hex.Decode(key, hexCandidate); err != nil {
			ZeroBuffer(key)
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		return key, nil
	}

	// Only strip a trailing editor/CLI line ending (\r\n or \n) for printable 32-byte text keys;
	// non-printable payloads (e.g. a corrupted 33-byte binary file ending in 0x0A) must never be truncated to 32 bytes.
	lineTrimmed := trimSingleTrailingNewline(data)
	if len(lineTrimmed) == 32 && isPrintableASCII(lineTrimmed) {
		key := make([]byte, 32)
		copy(key, lineTrimmed)
		return key, nil
	}

	return nil, fmt.Errorf("%w: got %d %s", ErrInvalidKey, len(data), unit)
}

// isPrintableASCII reports whether all bytes in b are printable ASCII characters (0x20..0x7E).
func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// trimSingleTrailingNewline strips at most one trailing CRLF (\r\n) or LF (\n) line ending without trimming spaces.
func trimSingleTrailingNewline(b []byte) []byte {
	if bytes.HasSuffix(b, []byte("\r\n")) {
		return b[:len(b)-2]
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}

// readProtectedKeyFile opens a key file once, validates platform-specific security boundaries on the handle,
// and reads at most maxKeyInputBytes bytes.
//
// Objective:
// Prevent TOCTOU race conditions and reject master keys stored in special files or locations
// accessible to other users or inherently volatile/insecure.
//
// Enforcement:
// - Single os.Open + f.Stat() on the opened file handle, enforcing IsRegular() and <= maxKeyInputBytes.
// - Linux/Unix: Enforce no setuid/setgid/sticky bits, owner UID match (checkFileOwner), and 0400/0600 permissions.
// - Windows: Resolve symlinks/junctions and block shared Public/Temp/tmp directory segments.
func (d sysDeps) readProtectedKeyFile(ctx context.Context, path string) ([]byte, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	cleanPath := filepath.Clean(path)
	f, err := d.openFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat key file: %w", err)
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: key file must be a regular file", ErrInsecurePermissions)
	}

	if info.Size() > maxKeyInputBytes {
		return nil, fmt.Errorf("%w: key file exceeds %d bytes", ErrInvalidKey, maxKeyInputBytes)
	}

	if d.goos != "windows" {
		// Linux/Unix security: Ensure no special mode bits, owner-only permissions (0400/0600), and matching UID.
		mode := info.Mode()
		if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return nil, fmt.Errorf("%w: special mode bits disallowed (%o)", ErrInsecurePermissions, mode)
		}
		perm := mode.Perm()
		if perm != 0o400 && perm != 0o600 {
			return nil, fmt.Errorf("%w: %o (expected 0400 or 0600)", ErrInsecurePermissions, perm)
		}
		if err := checkFileOwner(info, d.geteuid); err != nil {
			return nil, err
		}
	} else {
		// Windows security: Canonicalize symlinks/junctions and block shared Public/Temp locations.
		if err := d.validateWindowsKeyPath(path, cleanPath); err != nil {
			return nil, err
		}
	}

	keyData, err := readBounded(f, maxKeyInputBytes)
	if err != nil {
		if errors.Is(err, errInputTooLarge) {
			return nil, fmt.Errorf("%w: key file exceeds %d bytes", ErrInvalidKey, maxKeyInputBytes)
		}
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	return keyData, nil
}

// validateWindowsKeyPath canonicalizes candidate and resolved symlink/junction paths on Windows
// and verifies none reside inside insecure shared or temporary directories.
func (d sysDeps) validateWindowsKeyPath(origPath, cleanPath string) error {
	candidates := []string{cleanPath}
	// Host filepath.Abs applies native separator/drive rules, so invoke it only when actually running on Windows.
	if runtime.GOOS == "windows" {
		if absPath, err := filepath.Abs(cleanPath); err == nil {
			candidates = append(candidates, absPath)
		}
	}
	if d.evalSymlinks != nil {
		for _, c := range append([]string(nil), candidates...) {
			resolved, err := d.evalSymlinks(c)
			if err != nil {
				return fmt.Errorf("%w: failed to resolve key path %s: %v", ErrInsecureLocation, origPath, err)
			}
			if resolved != "" {
				candidates = append(candidates, resolved)
			}
		}
	}

	tempCandidates := []string{}
	if td := d.tempDir(); td != "" {
		tempCandidates = append(tempCandidates, td)
		if d.evalSymlinks != nil {
			if resolvedTD, err := d.evalSymlinks(td); err == nil && resolvedTD != "" {
				tempCandidates = append(tempCandidates, resolvedTD)
			}
		}
	}

	for _, candidate := range candidates {
		if isInsecureWindowsPath(candidate, tempCandidates) {
			return fmt.Errorf("%w: %s", ErrInsecureLocation, origPath)
		}
	}
	return nil
}

// isInsecureWindowsPath checks normalized Windows paths against known Public/Temp roots
// and exact directory segment boundaries ("temp", "tmp", "users\public").
func isInsecureWindowsPath(path string, tempDirs []string) bool {
	normPath := normalizeWindowsPath(path)
	if normPath == "" {
		return false
	}

	blockedPrefixes := []string{
		`c:\users\public`,
		`c:\windows\temp`,
	}
	for _, td := range tempDirs {
		if normTD := normalizeWindowsPath(td); normTD != "" {
			blockedPrefixes = append(blockedPrefixes, normTD)
		}
	}

	for _, prefix := range blockedPrefixes {
		if normPath == prefix || strings.HasPrefix(normPath, prefix+`\`) {
			return true
		}
	}

	// Inspect only directory segments (excluding the final file name) to avoid false positives
	// on directory names like C:\Users\PublicAdmin or C:\Template.
	segments := strings.Split(strings.TrimPrefix(normPath, `\\`), `\`)
	if len(segments) <= 1 {
		return false
	}
	dirSegments := segments[:len(segments)-1]
	for i, seg := range dirSegments {
		if seg == "temp" || seg == "tmp" {
			return true
		}
		if seg == "users" && i+1 < len(dirSegments) && dirSegments[i+1] == "public" {
			return true
		}
	}
	return false
}

// normalizeWindowsPath canonicalizes separators, extended-length \\?\ / \\.\ prefixes,
// duplicate backslashes, and ASCII casing for reliable Windows path comparison.
func normalizeWindowsPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "/", `\`)
	lower := strings.ToLower(p)
	switch {
	case strings.HasPrefix(lower, `\\?\unc\`):
		p = `\\` + p[len(`\\?\unc\`):]
	case strings.HasPrefix(lower, `\\?\`):
		p = p[len(`\\?\`):]
	case strings.HasPrefix(lower, `\\.\`):
		p = p[len(`\\.\`):]
	}

	isUNC := strings.HasPrefix(p, `\\`)
	body := p
	if isUNC {
		body = strings.TrimLeft(p, `\`)
	}
	for strings.Contains(body, `\\`) {
		body = strings.ReplaceAll(body, `\\`, `\`)
	}
	body = strings.TrimRight(body, `\`)
	if isUNC {
		body = `\\` + body
	}
	return strings.ToLower(body)
}

// EncryptBytesWithAAD encrypts plaintext bytes with a 32-byte master key and optional
// additional authenticated data (AAD), returning v1:gcm:<base64(nonce + ciphertext)>.
//
// Data Flow:
// 1. Verify context has not been canceled and validate key length (exactly 32 bytes).
// 2. Initialize AES-256 block cipher and GCM mode.
// 3. Generate a 12-byte CSPRNG nonce via sysDeps.randReader.
// 4. Encrypt and seal payload with optional AAD, prepending nonce.
// 5. Base64 encode and prepend the v1:gcm: prefix.
func EncryptBytesWithAAD(ctx context.Context, plain, key, aad []byte) ([]byte, error) {
	return defaultDeps.encryptBytesWithAAD(ctx, plain, key, aad)
}

// encryptBytesWithAAD implements AES-256-GCM encryption against injected sysDeps.
func (d sysDeps) encryptBytesWithAAD(ctx context.Context, plain, key, aad []byte) ([]byte, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(d.randReader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plain, aad)
	base64Len := base64.StdEncoding.EncodedLen(len(ciphertext))
	buf := make([]byte, len(EncryptedPrefix)+base64Len)
	copy(buf, EncryptedPrefix)
	base64.StdEncoding.Encode(buf[len(EncryptedPrefix):], ciphertext)
	return buf, nil
}

// EncryptBytes takes a plaintext byte slice and a 32-byte master key, returning prefixed Base64-encoded bytes.
// Output format: v1:gcm:<base64(nonce + ciphertext)>
//
// Data Flow:
// 1. Validate key length (must be exactly 32 bytes).
// 2. Initialize AES-256 block cipher and GCM mode.
// 3. Generate a 12-byte CSPRNG nonce.
// 4. Encrypt and seal payload with nil AAD, prepending nonce.
// 5. Base64 encode and prepend v1:gcm: prefix.
func EncryptBytes(ctx context.Context, plain, key []byte) ([]byte, error) {
	return EncryptBytesWithAAD(ctx, plain, key, nil)
}

// EncryptWithAAD encrypts a plaintext string with a 32-byte key and optional AAD,
// scrubbing the temporary plaintext byte copy before returning.
func EncryptWithAAD(ctx context.Context, plain string, key, aad []byte) (string, error) {
	plainBytes := []byte(plain)
	defer ZeroBuffer(plainBytes)

	b, err := EncryptBytesWithAAD(ctx, plainBytes, key, aad)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Encrypt takes a plaintext string and a 32-byte key, returning a prefixed Base64-encoded string.
// Output format: v1:gcm:<base64(nonce + ciphertext)>
func Encrypt(ctx context.Context, plain string, key []byte) (string, error) {
	return EncryptWithAAD(ctx, plain, key, nil)
}

// DecryptBytesWithAAD decrypts and authenticates a prefixed or legacy raw Base64-encoded byte slice
// using a 32-byte master key and optional additional authenticated data (AAD).
//
// Data Flow:
// 1. Verify context has not been canceled and validate key length (32 bytes).
// 2. Trim whitespace and strip v1:gcm: prefix if present (rejecting unknown v<N>:<alg>: headers).
// 3. Base64 decode ciphertext into a deferred-zeroed buffer.
// 4. Validate minimum length against AES-GCM nonce + authentication tag size (28 bytes).
// 5. Decrypt and authenticate MAC tag (including optional AAD) using AES-256-GCM.
// 6. Return original plaintext bytes.
func DecryptBytesWithAAD(ctx context.Context, encoded, key, aad []byte) ([]byte, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}

	// Trim whitespace first, then strip v1:gcm: prefix if present (backwards compatible with raw base64)
	cleanEncoded := bytes.TrimSpace(encoded)
	if bytes.HasPrefix(cleanEncoded, []byte(EncryptedPrefix)) {
		cleanEncoded = cleanEncoded[len(EncryptedPrefix):]
		if len(cleanEncoded) == 0 {
			return nil, ErrCiphertextTooShort
		}
	} else if hasVersionPrefix(cleanEncoded) {
		previewLen := min(len(cleanEncoded), 16)
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedVersion, string(cleanEncoded[:previewLen]))
	}

	data := make([]byte, base64.StdEncoding.DecodedLen(len(cleanEncoded)))
	defer ZeroBuffer(data)

	n, err := base64.StdEncoding.Decode(data, cleanEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	data = data[:n]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	minLen := gcm.NonceSize() + gcm.Overhead()
	if len(data) < minLen {
		return nil, ErrCiphertextTooShort
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// DecryptBytes takes a prefixed or raw Base64-encoded byte slice and a 32-byte master key.
// Accepts both v1:gcm: prefixed values (new format) and raw base64 (backwards compatible).
//
// Data Flow:
// 1. Trim whitespace and strip v1:gcm: prefix if present.
// 2. Base64 decode raw ciphertext buffer.
// 3. Validate minimum length against AES-GCM nonce + tag overhead.
// 4. Decrypt and authenticate MAC tag using AES-256-GCM (nil AAD).
// 5. Return original plaintext bytes.
func DecryptBytes(ctx context.Context, encoded, key []byte) ([]byte, error) {
	return DecryptBytesWithAAD(ctx, encoded, key, nil)
}

// DecryptWithAAD decrypts a prefixed or raw Base64-encoded string with a 32-byte master key and optional AAD.
func DecryptWithAAD(ctx context.Context, encoded string, key, aad []byte) (string, error) {
	b, err := DecryptBytesWithAAD(ctx, []byte(encoded), key, aad)
	if err != nil {
		return "", err
	}
	defer ZeroBuffer(b)
	return string(b), nil
}

// Decrypt takes a prefixed or raw Base64-encoded string and a 32-byte master key.
// Accepts both v1:gcm: prefixed values (new format) and raw base64 (backwards compatible).
func Decrypt(ctx context.Context, encoded string, key []byte) (string, error) {
	return DecryptWithAAD(ctx, encoded, key, nil)
}
