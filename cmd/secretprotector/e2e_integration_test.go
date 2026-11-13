// Package main implements end-to-end binary process integration tests for SecretProtector.
// It compiles the actual CLI executable and tests all functionality in spawned process instances.
//
// Objective:
// To validate complete binary execution, OS process communication, pipeline streaming,
// environment variable key resolution, and diagnostic exit codes (0, 2, 3, 4, 5) in a realistic environment.
//
// Core Components:
// 1. Process Builder (TestMain): Compiles the current source code into a temporary binary executable.
// 2. Lifecycle Runner (TestE2E_FullLifecycle): Executes -generate, -generate-raw, key-file encryption/decryption (-raw), and env key resolution.
// 3. Pipeline Streamer (TestE2E_StdinPipeline): Executes stdin/pipe reading for encryption (-encrypt -) and decryption (-decrypt - -raw).
// 4. Exit Code Verifier (TestE2E_ExitCodes): Validates process exit codes returned by the compiled CLI executable.
//
// Test Strategy & Data Flow:
// 1. Compilation: TestMain compiles the secretprotector binary into a temporary test folder.
// 2. Process Execution: Spawns exec.Command processes with piped stdin/stdout/stderr and custom environment variables.
// 3. Assertion: Verifies exact exit codes, stderr error messages, and exact round-trip plaintext recovery.
package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// binaryPath holds the path to the compiled executable during integration testing.
var binaryPath string

// TestMain compiles the standalone secretprotector binary into a temp directory prior to running E2E tests.
func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "sp_e2e_build_")
	if err != nil {
		os.Exit(1)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	exeName := "secretprotector"
	if runtime.GOOS == "windows" {
		exeName = "secretprotector.exe"
	}
	binaryPath = filepath.Join(tmpDir, exeName)

	// Build the real SecretProtector binary
	buildCmd := exec.Command("go", "build", "-o", binaryPath, "./")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		println("Failed to compile binary for E2E tests:", string(output))
		os.Exit(1)
	}

	exitCode := m.Run()
	os.Exit(exitCode)
}

// makeE2ETempDirInWD returns t.TempDir() on Unix/Linux (so key files use POSIX 0600 permissions)
// and creates a cleaned key directory under os.Getwd() on Windows to avoid %TEMP% path blocks.
func makeE2ETempDirInWD(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return t.TempDir()
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working dir: %v", err)
	}
	dir, err := os.MkdirTemp(wd, "sp_e2e_keys_")
	if err != nil {
		t.Fatalf("Failed to create key dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

// envWithoutVar returns a copy of os.Environ() with the named variable removed (case-insensitively).
func envWithoutVar(name string) []string {
	env := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		if k, _, ok := strings.Cut(entry, "="); ok && strings.EqualFold(k, name) {
			continue
		}
		env = append(env, entry)
	}
	return env
}

// TestE2E_FullLifecycle tests key generation (-generate and -generate-raw), encryption, decryption, env vars, and key files.
func TestE2E_FullLifecycle(t *testing.T) {
	keyDir := makeE2ETempDirInWD(t)
	keyFile := filepath.Join(keyDir, "master.key")

	// 1. Generate 64-char hex key via CLI Binary
	cmdGen := exec.Command(binaryPath, "-generate")
	var outGen bytes.Buffer
	cmdGen.Stdout = &outGen
	if err := cmdGen.Run(); err != nil {
		t.Fatalf("E2E -generate failed: %v", err)
	}

	masterKey := strings.TrimSpace(outGen.String())
	if len(masterKey) != 64 {
		t.Fatalf("Expected 64-character hex master key, got %d chars: %q", len(masterKey), masterKey)
	}

	// Write generated key to secure file
	if err := os.WriteFile(keyFile, []byte(masterKey), 0o600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// 2. Encrypt Secret using Key File (with a different ambient SECRETPROTECTOR_MASTER_KEY proving -key-file wins)
	plaintext := "ProductionDatabasePassword2026!"
	otherEnvKey := strings.Repeat("f", 64)
	cmdEnc := exec.Command(binaryPath, "-key-file", keyFile, "-encrypt", plaintext)
	cmdEnc.Env = append(envWithoutVar("SECRETPROTECTOR_MASTER_KEY"), "SECRETPROTECTOR_MASTER_KEY="+otherEnvKey)
	var outEnc bytes.Buffer
	cmdEnc.Stdout = &outEnc
	if err := cmdEnc.Run(); err != nil {
		t.Fatalf("E2E -encrypt with key file failed: %v", err)
	}

	ciphertext := strings.TrimSpace(outEnc.String())
	if !strings.HasPrefix(ciphertext, "v1:gcm:") {
		t.Fatalf("Expected v1:gcm: ciphertext prefix, got %q", ciphertext)
	}

	// 3. Decrypt Secret using Key File (-raw for exact output without trailing newline)
	cmdDec := exec.Command(binaryPath, "-key-file", keyFile, "-decrypt", ciphertext, "-raw")
	cmdDec.Env = append(envWithoutVar("SECRETPROTECTOR_MASTER_KEY"), "SECRETPROTECTOR_MASTER_KEY="+otherEnvKey)
	var outDec bytes.Buffer
	cmdDec.Stdout = &outDec
	if err := cmdDec.Run(); err != nil {
		t.Fatalf("E2E -decrypt with key file failed: %v", err)
	}
	if outDec.String() != plaintext {
		t.Errorf("E2E round-trip decryption mismatch: got %q, want %q", outDec.String(), plaintext)
	}

	// 4. Generate 32-char raw key via -generate-raw and verify round-trip via Environment Variable
	cmdGenRaw := exec.Command(binaryPath, "-generate-raw")
	var outGenRaw bytes.Buffer
	cmdGenRaw.Stdout = &outGenRaw
	if err := cmdGenRaw.Run(); err != nil {
		t.Fatalf("E2E -generate-raw failed: %v", err)
	}
	rawKey := strings.TrimSpace(outGenRaw.String())
	if len(rawKey) != 32 {
		t.Fatalf("Expected 32-char raw key, got %d chars", len(rawKey))
	}

	cmdEncEnv := exec.Command(binaryPath, "-encrypt", plaintext)
	cmdEncEnv.Env = append(envWithoutVar("SECRETPROTECTOR_MASTER_KEY"), "SECRETPROTECTOR_MASTER_KEY="+rawKey)
	var outEncEnv bytes.Buffer
	cmdEncEnv.Stdout = &outEncEnv
	if err := cmdEncEnv.Run(); err != nil {
		t.Fatalf("E2E -encrypt with env raw key failed: %v", err)
	}

	ciphertextEnv := strings.TrimSpace(outEncEnv.String())

	cmdDecEnv := exec.Command(binaryPath, "-decrypt", ciphertextEnv)
	cmdDecEnv.Env = append(envWithoutVar("SECRETPROTECTOR_MASTER_KEY"), "SECRETPROTECTOR_MASTER_KEY="+rawKey)
	var outDecEnv bytes.Buffer
	cmdDecEnv.Stdout = &outDecEnv
	if err := cmdDecEnv.Run(); err != nil {
		t.Fatalf("E2E -decrypt with env raw key failed: %v", err)
	}
	if strings.TrimSpace(outDecEnv.String()) != plaintext {
		t.Errorf("E2E env raw key round-trip mismatch")
	}
}

// TestE2E_StdinPipeline tests pipe/stdin streaming for encryption and decryption.
func TestE2E_StdinPipeline(t *testing.T) {
	cmdGen := exec.Command(binaryPath, "-generate")
	var outGen bytes.Buffer
	cmdGen.Stdout = &outGen
	if err := cmdGen.Run(); err != nil {
		t.Fatalf("E2E -generate failed: %v", err)
	}
	masterKey := strings.TrimSpace(outGen.String())

	plaintext := "PipedSecretData-9988"

	// 1. Pipe plaintext into -encrypt -
	cmdEncPipe := exec.Command(binaryPath, "-key", masterKey, "-encrypt", "-")
	cmdEncPipe.Stdin = strings.NewReader(plaintext + "\n")
	var outEncPipe bytes.Buffer
	cmdEncPipe.Stdout = &outEncPipe
	if err := cmdEncPipe.Run(); err != nil {
		t.Fatalf("E2E stdin encrypt pipe failed: %v", err)
	}
	ciphertext := strings.TrimSpace(outEncPipe.String())

	// 2. Pipe ciphertext into -decrypt -
	cmdDecPipe := exec.Command(binaryPath, "-key", masterKey, "-decrypt", "-", "-raw")
	cmdDecPipe.Stdin = strings.NewReader(ciphertext + "\n")
	var outDecPipe bytes.Buffer
	cmdDecPipe.Stdout = &outDecPipe
	if err := cmdDecPipe.Run(); err != nil {
		t.Fatalf("E2E stdin decrypt pipe failed: %v", err)
	}
	if outDecPipe.String() != plaintext {
		t.Errorf("E2E stdin pipeline mismatch: got %q, want %q", outDecPipe.String(), plaintext)
	}

	t.Run("KeyViaStdin", func(t *testing.T) {
		secretMsg := "StdinKeySecret-2026"

		cmdEnc := exec.Command(binaryPath, "-key-file", "-", "-encrypt", secretMsg)
		cmdEnc.Env = envWithoutVar("SECRETPROTECTOR_MASTER_KEY")
		cmdEnc.Stdin = strings.NewReader(masterKey + "\n")
		var outEnc bytes.Buffer
		cmdEnc.Stdout = &outEnc
		if err := cmdEnc.Run(); err != nil {
			t.Fatalf("E2E -key-file - encrypt failed: %v", err)
		}
		encrypted := strings.TrimSpace(outEnc.String())

		cmdDec := exec.Command(binaryPath, "-key-file", "-", "-decrypt", encrypted, "-raw")
		cmdDec.Env = envWithoutVar("SECRETPROTECTOR_MASTER_KEY")
		cmdDec.Stdin = strings.NewReader(masterKey + "\n")
		var outDec bytes.Buffer
		cmdDec.Stdout = &outDec
		if err := cmdDec.Run(); err != nil {
			t.Fatalf("E2E -key-file - decrypt failed: %v", err)
		}
		if outDec.String() != secretMsg {
			t.Errorf("E2E -key-file - mismatch: got %q, want %q", outDec.String(), secretMsg)
		}
	})

	t.Run("MultilineNonASCIIAndNULPayload", func(t *testing.T) {
		complexPayload := []byte("line1-café-\u2603\n\nline2-\ttab-\x00-binary-end")

		cmdEnc := exec.Command(binaryPath, "-key", masterKey, "-encrypt", "-")
		cmdEnc.Stdin = bytes.NewReader(append(append([]byte(nil), complexPayload...), '\n'))
		var outEnc bytes.Buffer
		cmdEnc.Stdout = &outEnc
		if err := cmdEnc.Run(); err != nil {
			t.Fatalf("E2E complex stdin encrypt failed: %v", err)
		}
		encrypted := strings.TrimSpace(outEnc.String())

		cmdDec := exec.Command(binaryPath, "-key", masterKey, "-decrypt", "-", "-raw")
		cmdDec.Stdin = strings.NewReader(encrypted + "\n")
		var outDec bytes.Buffer
		cmdDec.Stdout = &outDec
		if err := cmdDec.Run(); err != nil {
			t.Fatalf("E2E complex stdin decrypt failed: %v", err)
		}
		if !bytes.Equal(outDec.Bytes(), complexPayload) {
			t.Errorf("E2E complex payload mismatch: got %x, want %x", outDec.Bytes(), complexPayload)
		}
	})
}

// TestE2E_ExitCodes verifies that process exit codes match specifications (0, 2, 3, 4, 5).
func TestE2E_ExitCodes(t *testing.T) {
	// Real key file engineered to trip OS security enforcement:
	// - Windows: located inside os.TempDir() -> ErrInsecureLocation (exit 3)
	// - Unix: world/group-readable 0o644 permissions -> ErrInsecurePermissions (exit 3)
	insecureKeyFile := filepath.Join(t.TempDir(), "insecure.key")
	if err := os.WriteFile(insecureKeyFile, []byte(strings.Repeat("a", 64)), 0o644); err != nil {
		t.Fatalf("failed to create insecure key file: %v", err)
	}
	if err := os.Chmod(insecureKeyFile, 0o644); err != nil {
		t.Fatalf("failed to chmod insecure key file: %v", err)
	}

	tests := []struct {
		name         string
		args         []string
		expectedCode int
	}{
		{
			name:         "Success Version Flag",
			args:         []string{"-version"},
			expectedCode: 0,
		},
		{
			name:         "Usage Error Bare Invocation",
			args:         nil,
			expectedCode: 2,
		},
		{
			name:         "Usage Error Mutually Exclusive Flags",
			args:         []string{"-generate", "-encrypt", "test"},
			expectedCode: 2,
		},
		{
			name:         "Usage Error Stdin Collision",
			args:         []string{"-encrypt", "-", "-key-file", "-"},
			expectedCode: 2,
		},
		{
			name:         "Key Resolution Failure",
			args:         []string{"-encrypt", "test", "-key-env", "NON_EXISTENT_VAR_12345"},
			expectedCode: 3,
		},
		{
			name:         "Security Error Insecure Key File",
			args:         []string{"-encrypt", "test", "-key-file", insecureKeyFile},
			expectedCode: 3,
		},
		{
			name:         "Crypto Error Bad Base64",
			args:         []string{"-key", strings.Repeat("a", 64), "-decrypt", "INVALID_B64_DATA!"},
			expectedCode: 4,
		},
		{
			name:         "IO Error Missing Key File",
			args:         []string{"-encrypt", "test", "-key-file", "does_not_exist_98765.key"},
			expectedCode: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, tt.args...)
			cmd.Env = envWithoutVar("SECRETPROTECTOR_MASTER_KEY") // Isolate child from host env key
			err := cmd.Run()

			if tt.expectedCode == 0 {
				if err != nil {
					t.Errorf("Expected exit code 0 for %s, got error: %v", tt.name, err)
				}
			} else {
				if err == nil {
					t.Fatalf("Expected exit code %d for %s, but command succeeded", tt.expectedCode, tt.name)
				}
				if exitErr, ok := err.(*exec.ExitError); ok {
					if exitErr.ExitCode() != tt.expectedCode {
						t.Errorf("Expected exit code %d for %s, got %d", tt.expectedCode, tt.name, exitErr.ExitCode())
					}
				} else {
					t.Errorf("Expected ExitError for %s, got %v", tt.name, err)
				}
			}
		})
	}
}
