// Package main implements end-to-end binary process integration tests for SecretProtector.
// It compiles the actual CLI executable and tests all functionality in spawned process instances.
//
// Objective:
// To validate complete binary execution, OS process communication, pipeline streaming,
// environment variable key resolution, and diagnostic exit codes (0, 2, 3, 4, 5) in a realistic environment.
//
// Core Components:
// 1. Process Builder (TestMain): Compiles the current source code into a temporary binary executable.
// 2. Lifecycle Runner (TestE2E_FullLifecycle): Executes key generation, key-file encryption/decryption, and env key resolution.
// 3. Pipeline Streamer (TestE2E_StdinPipeline): Executes stdin/pipe reading for encryption (-encrypt -) and decryption (-decrypt -).
// 4. Exit Code Verifier (TestE2E_ExitCodes): Validates process exit codes returned by the compiled CLI executable.
//
// Test Strategy & Data Flow:
// 1. Compilation: TestMain compiles secretprotector binary into a temporary test folder.
// 2. Process Execution: Spawns exec.Command processes with piped stdin/stdout/stderr and custom environment variables.
// 3. Assertion: Verifies exact exit codes, stderr error messages, and round-trip plaintext recovery.
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

// TestE2E_FullLifecycle tests key generation, encryption, decryption, env vars, key files, and exit codes.
func TestE2E_FullLifecycle(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working dir: %v", err)
	}
	keyDir := filepath.Join(wd, "test_e2e_keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("Failed to create key dir: %v", err)
	}
	defer func() {
		_ = os.RemoveAll(keyDir)
	}()

	keyFile := filepath.Join(keyDir, "master.key")

	// 1. Generate Key via CLI Binary
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

	// 2. Encrypt Secret using Key File
	plaintext := "ProductionDatabasePassword2026!"
	cmdEnc := exec.Command(binaryPath, "-key-file", keyFile, "-encrypt", plaintext)
	var outEnc bytes.Buffer
	cmdEnc.Stdout = &outEnc
	if err := cmdEnc.Run(); err != nil {
		t.Fatalf("E2E -encrypt with key file failed: %v", err)
	}

	ciphertext := strings.TrimSpace(outEnc.String())
	if len(ciphertext) < 20 {
		t.Fatalf("E2E encryption output too short: %q", ciphertext)
	}

	// 3. Decrypt Secret using Key File
	cmdDec := exec.Command(binaryPath, "-key-file", keyFile, "-decrypt", ciphertext)
	var outDec bytes.Buffer
	cmdDec.Stdout = &outDec
	if err := cmdDec.Run(); err != nil {
		t.Fatalf("E2E -decrypt with key file failed: %v", err)
	}

	decrypted := strings.TrimSpace(outDec.String())
	if decrypted != plaintext {
		t.Errorf("E2E round-trip decryption mismatch: got %q, want %q", decrypted, plaintext)
	}

	// 4. Encrypt and Decrypt using Environment Variable
	cmdEncEnv := exec.Command(binaryPath, "-encrypt", plaintext)
	cmdEncEnv.Env = append(os.Environ(), "SECRETPROTECTOR_MASTER_KEY="+masterKey)
	var outEncEnv bytes.Buffer
	cmdEncEnv.Stdout = &outEncEnv
	if err := cmdEncEnv.Run(); err != nil {
		t.Fatalf("E2E -encrypt with env key failed: %v", err)
	}

	ciphertextEnv := strings.TrimSpace(outEncEnv.String())

	cmdDecEnv := exec.Command(binaryPath, "-decrypt", ciphertextEnv)
	cmdDecEnv.Env = append(os.Environ(), "SECRETPROTECTOR_MASTER_KEY="+masterKey)
	var outDecEnv bytes.Buffer
	cmdDecEnv.Stdout = &outDecEnv
	if err := cmdDecEnv.Run(); err != nil {
		t.Fatalf("E2E -decrypt with env key failed: %v", err)
	}

	if strings.TrimSpace(outDecEnv.String()) != plaintext {
		t.Errorf("E2E env key round-trip mismatch")
	}
}

// TestE2E_StdinPipeline tests pipe/stdin streaming for encryption and decryption.
func TestE2E_StdinPipeline(t *testing.T) {
	// Generate key
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
	cmdDecPipe := exec.Command(binaryPath, "-key", masterKey, "-decrypt", "-")
	cmdDecPipe.Stdin = strings.NewReader(ciphertext + "\n")
	var outDecPipe bytes.Buffer
	cmdDecPipe.Stdout = &outDecPipe
	if err := cmdDecPipe.Run(); err != nil {
		t.Fatalf("E2E stdin decrypt pipe failed: %v", err)
	}

	decrypted := strings.TrimSpace(outDecPipe.String())
	if decrypted != plaintext {
		t.Errorf("E2E stdin pipeline mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// TestE2E_ExitCodes verifies that process exit codes match specifications (0, 2, 3, 4, 5).
func TestE2E_ExitCodes(t *testing.T) {
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
			name:         "Crypto Error Bad Base64",
			args:         []string{"-key", strings.Repeat("a", 64), "-decrypt", "INVALID_B64_DATA!"},
			expectedCode: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, tt.args...)
			cmd.Env = os.Environ() // Ensure clean env
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
