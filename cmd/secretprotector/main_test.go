// Package main implements the integration tests for the SecretProtector CLI.
// It verifies the command-line interface by mocking arguments, capturing output,
// and ensuring the end-to-end flow from flags to library execution is correct.
//
// Test Strategy:
// 1. CLI Execution Model:
//   - Mocks os.Args and redirects os.Stdout/os.Stderr to capture and verify CLI output.
//   - Uses a custom FlagSet for each test to ensure isolation between test runs.
//
// 2. Functional Verification:
//   - Versioning: Ensures the -version flag correctly reports the build version.
//   - Key Generation: Validates that -generate produces a valid 64-character hex string.
//   - Integration: Performs end-to-end encryption and decryption via CLI flags.
//
// 3. Key Source Resolution:
//   - Verifies that keys can be provided via CLI flags, Environment Variables, and Files.
//   - Ensures the CLI correctly delegates resolution to the underlying library.
//
// 4. Error Resilience:
//   - Tests common failure modes: missing keys, invalid key formats, and malformed ciphertexts.
//   - Verifies that library errors (e.g., CSPRNG failure) are correctly bubbled up to the CLI.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"
)

// TestMainCLI verifies the CLI flag parsing and basic execution flows.
// It mocks os.Args and captures stdout/stderr to verify behavior.
func TestMainCLI(t *testing.T) {
	// Save original args and restore after test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	tests := []struct {
		name           string
		args           []string
		expectedOutput string
		expectError    bool
	}{
		{
			name:           "Version Flag",
			args:           []string{"cmd", "-version"},
			expectedOutput: "SecretProtector version: dev",
			expectError:    false,
		},
		{
			name:           "Generate Flag",
			args:           []string{"cmd", "-generate"},
			expectedOutput: "", // Output is a random hex string
			expectError:    false,
		},
		{
			name:           "No Flags (Usage)",
			args:           []string{"cmd"},
			expectedOutput: "Usage of cmd:",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args

			// Reset flags for each test case
			flag.CommandLine = flag.NewFlagSet(tt.args[0], flag.ContinueOnError)

			// Capture stdout
			oldStdout := os.Stdout
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stdout = w
			os.Stderr = w

			// Run main (we use a wrapper to avoid os.Exit)
			if err := runMain(context.Background()); err != nil {
				if !tt.expectError {
					t.Errorf("runMain() unexpected error: %v", err)
				}
			}

			if err := w.Close(); err != nil {
				t.Errorf("w.Close() error: %v", err)
			}
			var buf bytes.Buffer
			if _, err := buf.ReadFrom(r); err != nil {
				t.Errorf("buf.ReadFrom() error: %v", err)
			}
			os.Stdout = oldStdout
			os.Stderr = oldStderr

			output := strings.TrimSpace(buf.String())

			if tt.name == "Version Flag" && !strings.Contains(output, tt.expectedOutput) {
				t.Errorf("Expected output containing %q, got %q", tt.expectedOutput, output)
			}
			if tt.name == "Generate Flag" && len(output) != 64 {
				t.Errorf("Expected 64-char hex string for generate, got %d chars", len(output))
			}
		})
	}
}

// TestCLIEncryptionDecryption verifies the integration between CLI and library.
func TestCLIEncryptionDecryption(t *testing.T) {
	key, _ := libsecsecrets.GenerateKey()
	plaintext := "test-secret-123"

	// 1. Test Encryption
	os.Args = []string{"cmd", "-key", key, "-encrypt", plaintext}
	flag.CommandLine = flag.NewFlagSet("cmd", flag.ContinueOnError)

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = wErr
	if err := runMain(context.Background()); err != nil {
		t.Errorf("runMain() error: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("w.Close() error: %v", err)
	}
	_ = wErr.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Errorf("buf.ReadFrom() error: %v", err)
	}
	_ = rErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	encrypted := strings.TrimSpace(buf.String())
	if len(encrypted) < 20 {
		t.Fatalf("Encryption failed, output too short: %q", encrypted)
	}

	// 1a. Test Encryption via Env
	if err := os.Setenv("SECRETPROTECTOR_MASTER_KEY", key); err != nil {
		t.Fatalf("os.Setenv() error: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("SECRETPROTECTOR_MASTER_KEY"); err != nil {
			t.Errorf("os.Unsetenv() error: %v", err)
		}
	}()
	os.Args = []string{"cmd", "-encrypt", plaintext}
	flag.CommandLine = flag.NewFlagSet("cmd", flag.ContinueOnError)

	r1e, w1e, _ := os.Pipe()
	r1eErr, w1eErr, _ := os.Pipe()
	os.Stdout = w1e
	os.Stderr = w1eErr
	if err := runMain(context.Background()); err != nil {
		t.Errorf("runMain() error: %v", err)
	}
	if err := w1e.Close(); err != nil {
		t.Errorf("w1e.Close() error: %v", err)
	}
	_ = w1eErr.Close()
	var buf1e bytes.Buffer
	if _, err := buf1e.ReadFrom(r1e); err != nil {
		t.Errorf("buf1e.ReadFrom() error: %v", err)
	}
	_ = r1eErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	if len(strings.TrimSpace(buf1e.String())) < 20 {
		t.Errorf("Encryption via Env failed")
	}

	// 1b. Test Encryption via File
	tmpFile := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(tmpFile, []byte(key), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error: %v", err)
	}
	os.Args = []string{"cmd", "-key-file", tmpFile, "-encrypt", plaintext}
	flag.CommandLine = flag.NewFlagSet("cmd", flag.ContinueOnError)

	r1f, w1f, _ := os.Pipe()
	r1fErr, w1fErr, _ := os.Pipe()
	os.Stdout = w1f
	os.Stderr = w1fErr
	if err := runMain(context.Background()); err != nil {
		t.Errorf("runMain() error: %v", err)
	}
	if err := w1f.Close(); err != nil {
		t.Errorf("w1f.Close() error: %v", err)
	}
	_ = w1fErr.Close()
	var buf1f bytes.Buffer
	if _, err := buf1f.ReadFrom(r1f); err != nil {
		t.Errorf("buf1f.ReadFrom() error: %v", err)
	}
	_ = r1fErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	if len(strings.TrimSpace(buf1f.String())) < 20 {
		t.Errorf("Encryption via File failed")
	}

	// 2. Test Decryption
	os.Args = []string{"cmd", "-key", key, "-decrypt", encrypted}
	flag.CommandLine = flag.NewFlagSet("cmd", flag.ContinueOnError)

	r2, w2, _ := os.Pipe()
	r2Err, w2Err, _ := os.Pipe()
	os.Stdout = w2
	os.Stderr = w2Err
	if err := runMain(context.Background()); err != nil {
		t.Errorf("runMain() error: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Errorf("w2.Close() error: %v", err)
	}
	_ = w2Err.Close()
	var buf2 bytes.Buffer
	if _, err := buf2.ReadFrom(r2); err != nil {
		t.Errorf("buf2.ReadFrom() error: %v", err)
	}
	_ = r2Err.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	decrypted := strings.TrimSpace(buf2.String())
	if decrypted != plaintext {
		t.Errorf("Decryption failed: expected %q, got %q", plaintext, decrypted)
	}
}

// TestCLIStdinStream verifies pipe and stdin streaming integration.
func TestCLIStdinStream(t *testing.T) {
	key, _ := libsecsecrets.GenerateKey()
	plaintext := "stdin-secret-789"

	oldStdin := os.Stdin
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	defer func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()

	// 1. Test Encrypt via Stdin (-encrypt -)
	rIn, wIn, _ := os.Pipe()
	go func() {
		_, _ = wIn.WriteString(plaintext + "\n")
		_ = wIn.Close()
	}()
	os.Stdin = rIn

	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout = wOut
	os.Stderr = wErr

	os.Args = []string{"cmd", "-key", key, "-encrypt", "-"}
	flag.CommandLine = flag.NewFlagSet("cmd", flag.ContinueOnError)

	if err := runMain(context.Background()); err != nil {
		t.Fatalf("runMain encrypt stdin error: %v", err)
	}
	_ = wOut.Close()
	_ = wErr.Close()

	var bufOut bytes.Buffer
	_, _ = bufOut.ReadFrom(rOut)
	_ = rIn.Close()
	_ = rOut.Close()
	_ = rErr.Close()

	encryptedStdin := strings.TrimSpace(bufOut.String())
	if len(encryptedStdin) < 20 {
		t.Fatalf("Encryption via Stdin failed, output too short: %q", encryptedStdin)
	}

	// 2. Test Decrypt via Stdin (-decrypt -)
	rIn2, wIn2, _ := os.Pipe()
	go func() {
		_, _ = wIn2.WriteString(encryptedStdin + "\n")
		_ = wIn2.Close()
	}()
	os.Stdin = rIn2

	rOut2, wOut2, _ := os.Pipe()
	rErr2, wErr2, _ := os.Pipe()
	os.Stdout = wOut2
	os.Stderr = wErr2

	os.Args = []string{"cmd", "-key", key, "-decrypt", "-"}
	flag.CommandLine = flag.NewFlagSet("cmd", flag.ContinueOnError)

	if err := runMain(context.Background()); err != nil {
		t.Fatalf("runMain decrypt stdin error: %v", err)
	}
	_ = wOut2.Close()
	_ = wErr2.Close()

	var bufOut2 bytes.Buffer
	_, _ = bufOut2.ReadFrom(rOut2)
	_ = rIn2.Close()
	_ = rOut2.Close()
	_ = rErr2.Close()

	decryptedStdin := strings.TrimSpace(bufOut2.String())
	if decryptedStdin != plaintext {
		t.Errorf("Decryption via Stdin failed: expected %q, got %q", plaintext, decryptedStdin)
	}
}

// TestCLIErrorPaths verifies error handling in the CLI.
func TestCLIErrorPaths(t *testing.T) {
	oldArgs := os.Args
	oldStderr := os.Stderr
	defer func() {
		os.Args = oldArgs
		os.Stderr = oldStderr
	}()

	tests := []struct {
		name         string
		args         []string
		expectedCode int
	}{
		{
			name:         "Encrypt without key",
			args:         []string{"cmd", "-encrypt", "secret", "-key-env", "NON_EXISTENT_ENV"},
			expectedCode: ExitKeyResolutionError,
		},
		{
			name:         "Decrypt with invalid key",
			args:         []string{"cmd", "-key", "invalid", "-decrypt", "base64"},
			expectedCode: ExitKeyResolutionError,
		},
		{
			name:         "Decrypt with invalid base64",
			args:         []string{"cmd", "-key", strings.Repeat("a", 64), "-decrypt", "!!!@#$"},
			expectedCode: ExitCryptoError,
		},
		{
			name:         "Encryption failure (mocked error)",
			args:         []string{"cmd", "-key", strings.Repeat("a", 64), "-encrypt", "secret"},
			expectedCode: ExitCryptoError,
		},
		{
			name:         "Decryption failure (mocked error)",
			args:         []string{"cmd", "-key", strings.Repeat("a", 64), "-decrypt", "A1B2C3D4"},
			expectedCode: ExitCryptoError,
		},
		{
			name:         "Mutually exclusive flags",
			args:         []string{"cmd", "-generate", "-encrypt", "secret"},
			expectedCode: ExitUsageError,
		},
		{
			name:         "Stdin secret and key collision",
			args:         []string{"cmd", "-encrypt", "-", "-key-file", "-"},
			expectedCode: ExitUsageError,
		},
		{
			name:         "Key file error",
			args:         []string{"cmd", "-encrypt", "secret", "-key-file", "non_existent_key_file.txt"},
			expectedCode: ExitKeyResolutionError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args
			flag.CommandLine = flag.NewFlagSet(tt.args[0], flag.ContinueOnError)

			r, w, _ := os.Pipe()
			os.Stderr = w

			// Mock library errors for specific test cases
			if tt.name == "Encryption failure (mocked error)" {
				libsecsecrets.RandReader = strings.NewReader("") // Cause nonce gen failure
				defer func() { libsecsecrets.RandReader = rand.Reader }()
			}

			err := runMain(context.Background())

			if err := w.Close(); err != nil {
				t.Errorf("w.Close() error: %v", err)
			}
			var buf bytes.Buffer
			if _, err := buf.ReadFrom(r); err != nil {
				t.Errorf("buf.ReadFrom() error: %v", err)
			}
			if err == nil {
				t.Errorf("Expected error for %s, but got nil", tt.name)
			}
			if code := exitCode(err); code != tt.expectedCode {
				t.Errorf("Expected exit code %d for %s, got %d", tt.expectedCode, tt.name, code)
			}
			if buf.Len() == 0 {
				t.Errorf("Expected error output for %s, but got none", tt.name)
			}
		})
	}
}

// TestCLIGenerateError verifies error handling when key generation fails.
func TestCLIGenerateError(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-generate"}
	flag.CommandLine = flag.NewFlagSet("cmd", flag.ContinueOnError)

	libsecsecrets.RandReader = strings.NewReader("") // Cause key gen failure
	defer func() { libsecsecrets.RandReader = rand.Reader }()

	err := runMain(context.Background())
	if err == nil {
		t.Error("Expected error from runMain when key generation fails, but got nil")
	}
	if code := exitCode(err); code != ExitCryptoError {
		t.Errorf("Expected ExitCryptoError (%d), got %d", ExitCryptoError, code)
	}
}

// TestExitErrorMethods tests exitError helper methods and exitCode mapping.
func TestExitErrorMethods(t *testing.T) {
	if code := exitCode(nil); code != ExitSuccess {
		t.Errorf("Expected ExitSuccess for nil error, got %d", code)
	}

	stdErr := errors.New("standard error")
	if code := exitCode(stdErr); code != 1 {
		t.Errorf("Expected code 1 for generic error, got %d", code)
	}

	customErr := &exitError{code: ExitIOError, err: stdErr}
	if customErr.Error() != "standard error" {
		t.Errorf("Expected customErr.Error() to be 'standard error', got %q", customErr.Error())
	}
	if !errors.Is(customErr, stdErr) {
		t.Errorf("Expected customErr.Unwrap() to match stdErr")
	}
	if code := exitCode(customErr); code != ExitIOError {
		t.Errorf("Expected code ExitIOError for customErr, got %d", code)
	}
}
