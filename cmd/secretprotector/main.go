// Package main implements the CLI utility for the SecretProtector system.
// It provides an administrative interface for generating master keys,
// as well as encrypting and decrypting secrets using the libsecsecrets library.
//
// Objective:
// To provide a standalone tool for DevOps and SecOps to manage the lifecycle
// of encrypted credentials without exposing plaintext values.
//
// Functionality:
// - Generate new 32-byte master keys (CSPRNG).
// - Encrypt plaintext strings using AES-256-GCM.
// - Decrypt Base64-encoded ciphertexts back to plaintext.
// - Support for multiple key sources (Flag, Environment, File) with strict security boundaries.
//
// Data Flow:
// 1. CLI Entry: Parse flags to determine operation (generate, encrypt, decrypt).
// 2. Key Acquisition: Call libsecsecrets.ResolveKey with flag-provided sources.
// 3. Transformation: Call appropriate libsecsecrets function based on operation.
// 4. Output: Write result to standard output or error to standard error.
// 5. Cleanup: Securely zero out key buffers (when possible) before termination.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"criticalsys.net/secretprotector/pkg/libsecsecrets"
)

// Exit code constants returned by SecretProtector to provide granular error diagnostic statuses:
// - ExitSuccess (0): Clean, successful execution.
// - ExitUsageError (2): Invalid flags, missing required arguments, or mutually exclusive options.
// - ExitKeyResolutionError (3): Unresolved master key or file permission check failure.
// - ExitCryptoError (4): Base64 decoding, MAC tag verification failure, or AES-GCM decryption error.
// - ExitIOError (5): File read/write failure or standard input streaming error.
const (
	ExitSuccess            = 0
	ExitUsageError         = 2
	ExitKeyResolutionError = 3
	ExitCryptoError        = 4
	ExitIOError            = 5
)

// exitError wraps a standard error with a specific process diagnostic exit code.
type exitError struct {
	code int
	err  error
}

// Error implements the standard error interface by returning the underlying error string.
func (e *exitError) Error() string {
	return e.err.Error()
}

// Unwrap enables standard Go error inspection and unwrapping via errors.Is and errors.As.
func (e *exitError) Unwrap() error {
	return e.err
}

// exitCode inspects an error and returns its associated numeric process exit status code.
// - If err is nil, returns ExitSuccess (0).
// - If err wraps an *exitError, returns its specific diagnostic code.
// - Otherwise, defaults to standard exit code 1.
func exitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return 1
}

// version is the application version, which can be overridden at compile time
// using -ldflags="-X main.version=..."
var version = "dev"

func main() {
	ctx := context.Background()
	if err := runMain(ctx); err != nil {
		os.Exit(exitCode(err))
	}
}

// runMain is the primary entry point for the CLI logic.
// It handles flag parsing, key resolution, and dispatches to library functions.
func runMain(ctx context.Context) error {
	// CLI Flag Definitions
	versionFlag := flag.Bool("version", false, "Print the version information and exit")
	generateFlag := flag.Bool("generate", false, "Generate a new 32-byte Master Key (64-char hex string)")
	encryptFlag := flag.String("encrypt", "", "Plaintext string to obfuscate")
	decryptFlag := flag.String("decrypt", "", "Base64-encoded ciphertext to decrypt")

	// Key Source Configuration Flags
	keyFlag := flag.String("key", "", "Provide the Master Key directly as a 64-character hex string")
	keyEnvFlag := flag.String("key-env", libsecsecrets.DefaultKeyEnv, "The name of the environment variable containing the Master Key")
	keyFileFlag := flag.String("key-file", "", "The fully qualified path to a file containing the Master Key")

	flag.Parse()

	// Execution Flow: Version Check
	if *versionFlag {
		fmt.Printf("SecretProtector version: %s\n", version)
		return nil
	}

	// Validate Flag Mutual Exclusivity
	actionCount := 0
	if *generateFlag {
		actionCount++
	}
	if *encryptFlag != "" {
		actionCount++
	}
	if *decryptFlag != "" {
		actionCount++
	}

	if actionCount > 1 {
		err := fmt.Errorf("conflicting options: -generate, -encrypt, and -decrypt are mutually exclusive")
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return &exitError{code: ExitUsageError, err: err}
	}

	if (*encryptFlag == "-" || *decryptFlag == "-") && *keyFileFlag == "-" {
		err := fmt.Errorf("cannot read both secret payload and key file from stdin simultaneously")
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return &exitError{code: ExitUsageError, err: err}
	}

	// Warn on command-line argument secret exposure
	if *keyFlag != "" {
		fmt.Fprintln(os.Stderr, "Warning: Passing sensitive master keys directly via CLI flags risks process listing exposure (ps aux). Prefer -key-env or -key-file.")
	}
	if *encryptFlag != "" && *encryptFlag != "-" {
		fmt.Fprintln(os.Stderr, "Warning: Passing plaintext secrets directly via CLI flags risks process listing exposure (ps aux). Prefer stdin (-encrypt -).")
	}

	// Execution Flow: Key Generation
	if *generateFlag {
		key, err := libsecsecrets.GenerateKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
			return &exitError{code: ExitCryptoError, err: err}
		}
		fmt.Println(key)
		return nil
	}

	// Execution Flow: Encryption
	if *encryptFlag != "" {
		plainText := *encryptFlag
		if plainText == "-" {
			inputBytes, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
				return &exitError{code: ExitIOError, err: err}
			}
			plainText = strings.TrimRight(string(inputBytes), "\r\n")
		}

		key, err := libsecsecrets.ResolveKey(ctx, *keyFlag, *keyEnvFlag, *keyFileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving key: %v\n", err)
			return &exitError{code: ExitKeyResolutionError, err: err}
		}
		defer libsecsecrets.ZeroBuffer(key)

		encrypted, err := libsecsecrets.Encrypt(ctx, plainText, key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encrypting: %v\n", err)
			return &exitError{code: ExitCryptoError, err: err}
		}
		fmt.Println(encrypted)
		return nil
	}

	// Execution Flow: Decryption
	if *decryptFlag != "" {
		cipherText := *decryptFlag
		if cipherText == "-" {
			inputBytes, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
				return &exitError{code: ExitIOError, err: err}
			}
			cipherText = strings.TrimSpace(string(inputBytes))
		}

		key, err := libsecsecrets.ResolveKey(ctx, *keyFlag, *keyEnvFlag, *keyFileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving key: %v\n", err)
			return &exitError{code: ExitKeyResolutionError, err: err}
		}
		defer libsecsecrets.ZeroBuffer(key)

		decrypted, err := libsecsecrets.Decrypt(ctx, cipherText, key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decrypting: %v\n", err)
			return &exitError{code: ExitCryptoError, err: err}
		}
		fmt.Println(decrypted)
		return nil
	}

	// Default: Show usage if no valid flags are provided.
	flag.Usage()
	return nil
}
