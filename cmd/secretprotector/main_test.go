// Package main implements the unit and in-process integration tests for the SecretProtector CLI.
// It verifies the command-line interface by injecting isolated stdio/library dependencies via runCLI,
// ensuring race-free test execution and complete validation from flags to library execution.
//
// Test Strategy:
// 1. CLI Execution Model:
//   - Injects isolated cliDeps (stdin/stdout/stderr buffers and crypto/key hooks) into runCLI.
//   - Exercises runMain(ctx) via a smoke test to verify default OS stdio and argument wiring.
//
// 2. Functional Verification:
//   - Versioning: Ensures -version correctly reports the build version.
//   - Key Generation: Validates that -generate produces a 64-char hex key and -generate-raw produces a 32-char Base64URL key.
//   - Integration: Performs end-to-end encryption, decryption, and -raw output formatting via CLI flags.
//
// 3. Key Source Resolution:
//   - Verifies that keys resolve cleanly via CLI flags, Environment Variables, and Files (isolated from env leakage).
//   - Ensures stdin streaming (-encrypt -, -decrypt -) preserves interior newlines while trimming a single trailing line ending.
//
// 4. Error Resilience:
//   - Tests common failure modes: unknown/extra args, empty values, no-op bare invocation, missing/invalid keys, malformed ciphertexts, and I/O errors.
//   - Verifies granular diagnostic exit codes (0, 2, 3, 4, 5) across all error classifications.
package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"
)

// errStreamReader fails every Read call with the configured error to test CLI stdin error paths.
type errStreamReader struct {
	err error
}

func (e errStreamReader) Read(_ []byte) (int, error) { return 0, e.err }

// errStreamWriter fails every Write call with the configured error to test CLI stdout ExitIOError mapping.
type errStreamWriter struct {
	err error
}

func (e errStreamWriter) Write(_ []byte) (int, error) { return 0, e.err }

// makeCLITestDirInWD returns t.TempDir() on Unix/Linux (so key files use POSIX 0600 permissions)
// and creates a temporary directory inside os.Getwd() on Windows so tests do not trigger %TEMP% restrictions.
func makeCLITestDirInWD(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return t.TempDir()
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd failed: %v", err)
	}
	dir, err := os.MkdirTemp(wd, "sp_clitest_")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

// newTestCLIDeps creates an isolated cliDeps instance wired to in-memory stdin/stdout/stderr buffers.
func newTestCLIDeps(stdinData string) (cliDeps, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	deps := defaultCLIDeps()
	deps.stdin = strings.NewReader(stdinData)
	deps.stdout = &stdout
	deps.stderr = &stderr
	return deps, &stdout, &stderr
}

// TestMainCLI verifies version, key generation, help, and no-args usage handling.
func TestMainCLI(t *testing.T) {
	t.Run("Version Flag", func(t *testing.T) {
		deps, out, errOut := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-version"}, deps); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out.String(), "SecretProtector version: ") {
			t.Errorf("expected version output, got %q", out.String())
		}
		if errOut.Len() != 0 {
			t.Errorf("unexpected stderr: %q", errOut.String())
		}
	})

	t.Run("Generate Flag", func(t *testing.T) {
		deps, out, _ := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-generate"}, deps); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := strings.TrimSpace(out.String())
		if len(got) != 64 {
			t.Errorf("expected 64-char hex key, got %d (%q)", len(got), got)
		}
	})

	t.Run("Generate Raw Flag", func(t *testing.T) {
		deps, out, _ := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-generate-raw"}, deps); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := strings.TrimSpace(out.String())
		if len(got) != 32 {
			t.Errorf("expected 32-char raw key, got %d (%q)", len(got), got)
		}
	})

	t.Run("Help Flag Exits 0", func(t *testing.T) {
		for _, flagName := range []string{"-h", "-help"} {
			deps, _, errOut := newTestCLIDeps("")
			if err := runCLI(context.Background(), []string{flagName}, deps); err != nil {
				t.Errorf("%s expected nil error, got %v", flagName, err)
			}
			if !strings.Contains(errOut.String(), "Usage of secretprotector:") {
				t.Errorf("%s expected usage text, got %q", flagName, errOut.String())
			}
		}
	})

	t.Run("No Flags Returns Usage Error", func(t *testing.T) {
		deps, _, errOut := newTestCLIDeps("")
		err := runCLI(context.Background(), nil, deps)
		if code := exitCode(err); code != ExitUsageError {
			t.Errorf("expected ExitUsageError (%d), got %d (err=%v)", ExitUsageError, code, err)
		}
		if !strings.Contains(errOut.String(), "Usage of secretprotector:") {
			t.Errorf("expected usage output on stderr, got %q", errOut.String())
		}
	})
}

// TestRunMainSmoke exercises the runMain wrapper with -version.
func TestRunMainSmoke(t *testing.T) {
	oldArgs := os.Args
	oldStdout := os.Stdout
	t.Cleanup(func() {
		os.Args = oldArgs
		os.Stdout = oldStdout
	})

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	os.Args = []string{"secretprotector", "-version"}
	os.Stdout = w

	runErr := runMain(context.Background())
	_ = w.Close()

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	_ = r.Close()

	if runErr != nil {
		t.Fatalf("runMain(-version) failed: %v", runErr)
	}
	if !strings.Contains(buf.String(), "SecretProtector version:") {
		t.Errorf("unexpected runMain output: %q", buf.String())
	}
}

// TestCLIEncryptionDecryption verifies CLI integration across direct key, env var, and file key sources.
func TestCLIEncryptionDecryption(t *testing.T) {
	key, err := libsecsecrets.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	plaintext := "test-secret-123"

	t.Run("DirectKeyAndStderrWarnings", func(t *testing.T) {
		deps, out, errOut := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-key", key, "-encrypt", plaintext}, deps); err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		encrypted := strings.TrimSpace(out.String())
		if !libsecsecrets.IsEncrypted(encrypted) {
			t.Fatalf("expected v1:gcm: output, got %q", encrypted)
		}
		if !strings.Contains(errOut.String(), "Warning: Passing sensitive master keys") {
			t.Errorf("expected -key exposure warning on stderr, got %q", errOut.String())
		}
		if !strings.Contains(errOut.String(), "Warning: Passing plaintext secrets") {
			t.Errorf("expected -encrypt exposure warning on stderr, got %q", errOut.String())
		}

		depsDec, outDec, _ := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-key", key, "-decrypt", encrypted}, depsDec); err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if outDec.String() != plaintext+"\n" {
			t.Errorf("expected %q, got %q", plaintext+"\n", outDec.String())
		}

		// -raw omits trailing newline
		depsRaw, outRaw, _ := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-key", key, "-decrypt", encrypted, "-raw"}, depsRaw); err != nil {
			t.Fatalf("decrypt -raw failed: %v", err)
		}
		if outRaw.String() != plaintext {
			t.Errorf("expected exact %q without newline, got %q", plaintext, outRaw.String())
		}
	})

	t.Run("EnvKey", func(t *testing.T) {
		t.Setenv(libsecsecrets.DefaultKeyEnv, key)
		deps, out, _ := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-encrypt", plaintext}, deps); err != nil {
			t.Fatalf("encrypt via env failed: %v", err)
		}
		encrypted := strings.TrimSpace(out.String())

		depsDec, outDec, _ := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-decrypt", encrypted}, depsDec); err != nil {
			t.Fatalf("decrypt via env failed: %v", err)
		}
		if strings.TrimSpace(outDec.String()) != plaintext {
			t.Errorf("env decrypt mismatch: got %q, want %q", outDec.String(), plaintext)
		}
	})

	t.Run("FileKeyOverridesDefaultEnv", func(t *testing.T) {
		// Ambient SECRETPROTECTOR_MASTER_KEY set to a DIFFERENT key must NOT override explicit -key-file.
		otherEnvKey, err := libsecsecrets.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		t.Setenv(libsecsecrets.DefaultKeyEnv, otherEnvKey)

		dir := makeCLITestDirInWD(t)
		keyFile := filepath.Join(dir, "master.key")
		fileKey, err := libsecsecrets.GenerateRawKey()
		if err != nil {
			t.Fatalf("GenerateRawKey failed: %v", err)
		}
		if err := os.WriteFile(keyFile, []byte(fileKey), 0o600); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		deps, out, _ := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-key-file", keyFile, "-encrypt", plaintext}, deps); err != nil {
			t.Fatalf("encrypt via file failed: %v", err)
		}
		encrypted := strings.TrimSpace(out.String())

		// Decrypting with ambient env alone (no -key-file) must fail because encryption used keyFile, not otherEnvKey.
		depsEnvOnly, _, _ := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-decrypt", encrypted}, depsEnvOnly); err == nil {
			t.Fatal("expected env-only decryption to fail when -key-file encrypted with a distinct key")
		}

		depsDec, outDec, _ := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-key-file", keyFile, "-decrypt", encrypted, "-raw"}, depsDec); err != nil {
			t.Fatalf("decrypt via file failed: %v", err)
		}
		if outDec.String() != plaintext {
			t.Errorf("file decrypt mismatch: got %q, want %q", outDec.String(), plaintext)
		}
	})

	t.Run("ExplicitEnvFlagWithFileFallback", func(t *testing.T) {
		customEnvName := "CUSTOM_SECRETPROTECTOR_KEY"
		customEnvKey, err := libsecsecrets.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		dir := makeCLITestDirInWD(t)
		keyFile := filepath.Join(dir, "master.key")
		fileKey, err := libsecsecrets.GenerateRawKey()
		if err != nil {
			t.Fatalf("GenerateRawKey failed: %v", err)
		}
		if err := os.WriteFile(keyFile, []byte(fileKey), 0o600); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		// When -key-env is explicitly specified and non-empty, it takes priority over -key-file.
		t.Setenv(customEnvName, customEnvKey)
		depsEncEnv, outEncEnv, _ := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-key-env", customEnvName, "-key-file", keyFile, "-encrypt", plaintext}, depsEncEnv); err != nil {
			t.Fatalf("encrypt with explicit -key-env and -key-file failed: %v", err)
		}
		encryptedViaEnv := strings.TrimSpace(outEncEnv.String())

		depsDecEnv, outDecEnv, _ := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-key-env", customEnvName, "-decrypt", encryptedViaEnv, "-raw"}, depsDecEnv); err != nil {
			t.Fatalf("decrypt via explicit -key-env failed: %v", err)
		}
		if outDecEnv.String() != plaintext {
			t.Errorf("explicit env decrypt mismatch: got %q, want %q", outDecEnv.String(), plaintext)
		}

		depsFileMismatch, _, _ := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-key-file", keyFile, "-decrypt", encryptedViaEnv}, depsFileMismatch); err == nil {
			t.Fatal("expected -key-file decryption to fail when ciphertext was encrypted with explicit -key-env")
		}

		// When the explicit -key-env variable is unset/empty, resolution falls back to -key-file.
		t.Setenv(customEnvName, "")
		depsEncFallback, outEncFallback, _ := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-key-env", customEnvName, "-key-file", keyFile, "-encrypt", plaintext}, depsEncFallback); err != nil {
			t.Fatalf("encrypt falling back to -key-file failed: %v", err)
		}
		encryptedViaFallback := strings.TrimSpace(outEncFallback.String())

		depsDecFallback, outDecFallback, _ := newTestCLIDeps("")
		if err := runCLI(context.Background(), []string{"-key-file", keyFile, "-decrypt", encryptedViaFallback, "-raw"}, depsDecFallback); err != nil {
			t.Fatalf("decrypt of -key-file fallback ciphertext failed: %v", err)
		}
		if outDecFallback.String() != plaintext {
			t.Errorf("fallback file decrypt mismatch: got %q, want %q", outDecFallback.String(), plaintext)
		}
	})
}

// TestCLIStdinStream verifies stdin streaming preserves interior newlines while trimming a single trailing line ending.
func TestCLIStdinStream(t *testing.T) {
	key, _ := libsecsecrets.GenerateKey()
	multiline := "line1\n\nline3"

	depsEnc, outEnc, errEnc := newTestCLIDeps(multiline + "\r\n")
	if err := runCLI(context.Background(), []string{"-key", key, "-encrypt", "-"}, depsEnc); err != nil {
		t.Fatalf("stdin encrypt failed: %v", err)
	}
	if strings.Contains(errEnc.String(), "Passing plaintext secrets") {
		t.Errorf("did not expect plaintext flag warning when using -encrypt -")
	}

	ciphertext := strings.TrimSpace(outEnc.String())

	depsDec, outDec, _ := newTestCLIDeps(ciphertext + "\n")
	if err := runCLI(context.Background(), []string{"-key", key, "-decrypt", "-", "-raw"}, depsDec); err != nil {
		t.Fatalf("stdin decrypt failed: %v", err)
	}
	if outDec.String() != multiline {
		t.Errorf("stdin round-trip mismatch: got %q, want %q", outDec.String(), multiline)
	}
}

// TestCLIErrorPaths verifies diagnostic exit codes (2, 3, 4, 5) and error reporting.
func TestCLIErrorPaths(t *testing.T) {
	t.Setenv(libsecsecrets.DefaultKeyEnv, "")

	tests := []struct {
		name         string
		args         []string
		setupDeps    func(cliDeps) cliDeps
		expectedCode int
	}{
		{
			name:         "Unknown flag",
			args:         []string{"-does-not-exist"},
			expectedCode: ExitUsageError,
		},
		{
			name:         "Unexpected positional argument",
			args:         []string{"-encrypt", "secret", "extra-arg"},
			expectedCode: ExitUsageError,
		},
		{
			name:         "Mutually exclusive flags",
			args:         []string{"-generate", "-encrypt", "secret"},
			expectedCode: ExitUsageError,
		},
		{
			name:         "Mutually exclusive generate and generate-raw",
			args:         []string{"-generate", "-generate-raw"},
			expectedCode: ExitUsageError,
		},
		{
			name:         "Mutually exclusive version and encrypt",
			args:         []string{"-version", "-encrypt", "secret"},
			expectedCode: ExitUsageError,
		},
		{
			name:         "Raw flag without decrypt",
			args:         []string{"-generate", "-raw"},
			expectedCode: ExitUsageError,
		},
		{
			name:         "Empty encrypt value",
			args:         []string{"-key", strings.Repeat("a", 64), "-encrypt", ""},
			expectedCode: ExitUsageError,
		},
		{
			name:         "Empty decrypt value",
			args:         []string{"-key", strings.Repeat("a", 64), "-decrypt", ""},
			expectedCode: ExitUsageError,
		},
		{
			name:         "Stdin secret and key collision",
			args:         []string{"-encrypt", "-", "-key-file", "-"},
			expectedCode: ExitUsageError,
		},
		{
			name:         "Encrypt without key",
			args:         []string{"-encrypt", "secret", "-key-env", "NON_EXISTENT_ENV"},
			expectedCode: ExitKeyResolutionError,
		},
		{
			name:         "Decrypt with invalid key",
			args:         []string{"-key", "invalid", "-decrypt", "base64"},
			expectedCode: ExitKeyResolutionError,
		},
		{
			name:         "Decrypt with invalid base64",
			args:         []string{"-key", strings.Repeat("a", 64), "-decrypt", "!!!@#$"},
			expectedCode: ExitCryptoError,
		},
		{
			name: "Encryption failure",
			args: []string{"-key", strings.Repeat("a", 64), "-encrypt", "secret"},
			setupDeps: func(d cliDeps) cliDeps {
				d.encryptBytes = func(context.Context, []byte, []byte) ([]byte, error) {
					return nil, errors.New("nonce failure")
				}
				return d
			},
			expectedCode: ExitCryptoError,
		},
		{
			name: "Generate failure",
			args: []string{"-generate"},
			setupDeps: func(d cliDeps) cliDeps {
				d.generateKey = func() (string, error) { return "", errors.New("entropy error") }
				return d
			},
			expectedCode: ExitCryptoError,
		},
		{
			name: "GenerateRaw failure",
			args: []string{"-generate-raw"},
			setupDeps: func(d cliDeps) cliDeps {
				d.generateRawKey = func() (string, error) { return "", errors.New("entropy error") }
				return d
			},
			expectedCode: ExitCryptoError,
		},
		{
			name:         "Non-existent key file returns IOError",
			args:         []string{"-encrypt", "secret", "-key-file", "non_existent_key_file_12345.txt"},
			expectedCode: ExitIOError,
		},
		{
			name: "Encrypt stdin read failure returns IOError",
			args: []string{"-key", strings.Repeat("a", 64), "-encrypt", "-"},
			setupDeps: func(d cliDeps) cliDeps {
				d.stdin = errStreamReader{err: errors.New("stdin broken")}
				return d
			},
			expectedCode: ExitIOError,
		},
		{
			name: "Decrypt stdin read failure returns IOError",
			args: []string{"-key", strings.Repeat("a", 64), "-decrypt", "-"},
			setupDeps: func(d cliDeps) cliDeps {
				d.stdin = errStreamReader{err: errors.New("stdin broken")}
				return d
			},
			expectedCode: ExitIOError,
		},
		{
			name: "Stdout write failure returns IOError",
			args: []string{"-generate"},
			setupDeps: func(d cliDeps) cliDeps {
				d.stdout = errStreamWriter{err: errors.New("broken pipe")}
				return d
			},
			expectedCode: ExitIOError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _, errOut := newTestCLIDeps("")
			if tt.setupDeps != nil {
				deps = tt.setupDeps(deps)
			}

			err := runCLI(context.Background(), tt.args, deps)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
			if code := exitCode(err); code != tt.expectedCode {
				t.Errorf("expected exit code %d for %s, got %d (err=%v)", tt.expectedCode, tt.name, code, err)
			}
			if errOut.Len() == 0 {
				t.Errorf("expected stderr output for %s", tt.name)
			}
		})
	}
}

// TestReadBoundedCLIAndLineTrimming verifies bounded stdin reading and CRLF/LF-only line-ending stripping.
func TestReadBoundedCLIAndLineTrimming(t *testing.T) {
	t.Parallel()
	if got, err := readBoundedCLI(strings.NewReader("1234567890"), 10); err != nil || string(got) != "1234567890" {
		t.Fatalf("readBoundedCLI exact limit failed: got %q err=%v", got, err)
	}
	if _, err := readBoundedCLI(strings.NewReader("12345678901"), 10); err == nil {
		t.Fatal("expected readBoundedCLI to fail when input exceeds limit")
	}

	if got := trimSingleLineEnding([]byte("abc\r\n")); string(got) != "abc" {
		t.Errorf("trimSingleLineEnding CRLF mismatch: got %q", got)
	}
	if got := trimSingleLineEnding([]byte("abc\r")); string(got) != "abc\r" {
		t.Errorf("expected standalone CR to be preserved, got %q", got)
	}
}

// TestExitErrorMethods tests exitError helper methods and exitCode mapping.
func TestExitErrorMethods(t *testing.T) {
	t.Parallel()
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
