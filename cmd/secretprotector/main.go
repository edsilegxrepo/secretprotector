// Package main implements the CLI utility for the SecretProtector system.
// It provides an administrative interface for generating master keys,
// as well as encrypting and decrypting secrets using the libsecsecrets library.
//
// Objective:
// To provide a standalone tool for DevOps and SecOps to manage the lifecycle
// of encrypted credentials without exposing plaintext values.
//
// Functionality:
// - Generate new 32-byte master keys (64-char hex via -generate, 32-char Base64URL via -generate-raw).
// - Encrypt plaintext payloads using AES-256-GCM (v1:gcm:...).
// - Decrypt prefixed or legacy Base64-encoded ciphertexts back to plaintext (with optional -raw output).
// - Support multiple key sources (Flag, Environment, File/Stdin) with strict security boundaries.
//
// Data Flow:
// 1. CLI Entry: Parse isolated FlagSet arguments to validate and determine operation (generate, generate-raw, encrypt, decrypt).
// 2. Key Acquisition: Call libsecsecrets.ResolveKey with flag-provided sources.
// 3. Transformation: Call appropriate libsecsecrets byte-slice API based on operation.
// 4. Output: Write result to standard output or structured diagnostic error to standard error.
// 5. Cleanup: Securely zero out key, plaintext, and temporary stdin buffers via ZeroBuffer before returning.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"
)

// Exit code constants returned by SecretProtector to provide granular error diagnostic statuses:
// - ExitSuccess (0): Clean, successful execution.
// - ExitUsageError (2): Invalid flags, missing required arguments, or mutually exclusive options.
// - ExitKeyResolutionError (3): Unresolved master key, invalid key format, or file security boundary failure.
// - ExitCryptoError (4): Base64 decoding, MAC tag verification failure, CSPRNG failure, or AES-GCM error.
// - ExitIOError (5): File read/write failure or standard I/O streaming error.
const (
	ExitSuccess            = 0
	ExitUsageError         = 2
	ExitKeyResolutionError = 3
	ExitCryptoError        = 4
	ExitIOError            = 5
)

// maxStdinSecretBytes bounds stdin payload reads for -encrypt - and -decrypt - to prevent OOM DoS.
const maxStdinSecretBytes = 10 * 1024 * 1024 // 10 MiB cap for piped CLI payloads

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

// cliDeps holds injected stdio streams and library operations so tests run runCLI without mutating globals.
type cliDeps struct {
	stdin          io.Reader
	stdout         io.Writer
	stderr         io.Writer
	generateKey    func() (string, error)
	generateRawKey func() (string, error)
	resolveKey     func(context.Context, string, string, string) ([]byte, error)
	encryptBytes   func(context.Context, []byte, []byte) ([]byte, error)
	decryptBytes   func(context.Context, []byte, []byte) ([]byte, error)
}

// defaultCLIDeps wires standard process stdio streams and libsecsecrets implementations.
func defaultCLIDeps() cliDeps {
	return cliDeps{
		stdin:          os.Stdin,
		stdout:         os.Stdout,
		stderr:         os.Stderr,
		generateKey:    libsecsecrets.GenerateKey,
		generateRawKey: libsecsecrets.GenerateRawKey,
		resolveKey:     libsecsecrets.ResolveKey,
		encryptBytes:   libsecsecrets.EncryptBytes,
		decryptBytes:   libsecsecrets.DecryptBytes,
	}
}

// main invokes runMain with a background context and maps returned errors to diagnostic exit codes.
func main() {
	ctx := context.Background()
	if err := runMain(ctx); err != nil {
		os.Exit(exitCode(err))
	}
}

// runMain is the primary entry point for the CLI logic using process arguments and stdio.
func runMain(ctx context.Context) error {
	return runCLI(ctx, os.Args[1:], defaultCLIDeps())
}

// runCLI parses CLI flags on an isolated FlagSet, enforces mutual exclusivity and exposure warnings,
// resolves the master key, executes the requested operation, and scrubs sensitive buffers on exit.
func runCLI(ctx context.Context, args []string, deps cliDeps) error {
	fs := flag.NewFlagSet("secretprotector", flag.ContinueOnError)
	fs.SetOutput(deps.stderr)

	// CLI Flag Definitions
	versionFlag := fs.Bool("version", false, "Print the version information and exit")
	generateFlag := fs.Bool("generate", false, "Generate a new 32-byte Master Key (64-char hex string)")
	generateRawFlag := fs.Bool("generate-raw", false, "Generate a new 32-char printable CSPRNG raw Master Key (Base64URL)")
	encryptFlag := fs.String("encrypt", "", "Plaintext string to obfuscate (or '-' for stdin)")
	decryptFlag := fs.String("decrypt", "", "Ciphertext to decrypt (or '-' for stdin)")
	rawFlag := fs.Bool("raw", false, "Omit trailing newline when printing decrypted output")

	// Key Source Configuration Flags
	keyFlag := fs.String("key", "", "Provide the Master Key directly (64-char hex or 32-byte raw)")
	keyEnvFlag := fs.String("key-env", libsecsecrets.DefaultKeyEnv, "The name of the environment variable containing the Master Key")
	keyFileFlag := fs.String("key-file", "", "The path to a file containing the Master Key (or '-' for stdin)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return &exitError{code: ExitUsageError, err: err}
	}

	visited := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})

	if fs.NArg() > 0 {
		err := fmt.Errorf("unexpected positional arguments: %v", fs.Args())
		fmt.Fprintf(deps.stderr, "Error: %v\n", err)
		return &exitError{code: ExitUsageError, err: err}
	}

	encryptSet := visited["encrypt"]
	decryptSet := visited["decrypt"]

	// Validate Flag Mutual Exclusivity
	actionCount := 0
	if *versionFlag {
		actionCount++
	}
	if *generateFlag {
		actionCount++
	}
	if *generateRawFlag {
		actionCount++
	}
	if encryptSet {
		actionCount++
	}
	if decryptSet {
		actionCount++
	}

	if actionCount > 1 {
		err := fmt.Errorf("conflicting options: -version, -generate, -generate-raw, -encrypt, and -decrypt are mutually exclusive")
		fmt.Fprintf(deps.stderr, "Error: %v\n", err)
		return &exitError{code: ExitUsageError, err: err}
	}

	if actionCount == 0 {
		fs.Usage()
		return &exitError{code: ExitUsageError, err: errors.New("no operation specified")}
	}

	if *rawFlag && !decryptSet {
		err := errors.New("-raw flag is only valid with -decrypt")
		fmt.Fprintf(deps.stderr, "Error: %v\n", err)
		return &exitError{code: ExitUsageError, err: err}
	}

	// Execution Flow: Version Check
	if *versionFlag {
		if _, err := fmt.Fprintf(deps.stdout, "SecretProtector version: %s\n", version); err != nil {
			fmt.Fprintf(deps.stderr, "Error writing output: %v\n", err)
			return &exitError{code: ExitIOError, err: err}
		}
		return nil
	}

	if encryptSet && *encryptFlag == "" {
		err := errors.New("-encrypt value cannot be empty (use -encrypt - for stdin)")
		fmt.Fprintf(deps.stderr, "Error: %v\n", err)
		return &exitError{code: ExitUsageError, err: err}
	}
	if decryptSet && *decryptFlag == "" {
		err := errors.New("-decrypt value cannot be empty (use -decrypt - for stdin)")
		fmt.Fprintf(deps.stderr, "Error: %v\n", err)
		return &exitError{code: ExitUsageError, err: err}
	}

	if (*encryptFlag == "-" || *decryptFlag == "-") && *keyFileFlag == "-" {
		err := fmt.Errorf("cannot read both secret payload and key file from stdin simultaneously")
		fmt.Fprintf(deps.stderr, "Error: %v\n", err)
		return &exitError{code: ExitUsageError, err: err}
	}

	// Warn on command-line argument secret exposure
	if *keyFlag != "" {
		fmt.Fprintln(deps.stderr, "Warning: Passing sensitive master keys directly via CLI flags risks process listing exposure (ps aux). Prefer -key-env or -key-file.")
	}
	if encryptSet && *encryptFlag != "-" {
		fmt.Fprintln(deps.stderr, "Warning: Passing plaintext secrets directly via CLI flags risks process listing exposure (ps aux). Prefer stdin (-encrypt -).")
	}

	// Execution Flow: Key Generation (64-char hex)
	if *generateFlag {
		key, err := deps.generateKey()
		if err != nil {
			fmt.Fprintf(deps.stderr, "Error generating key: %v\n", err)
			return &exitError{code: ExitCryptoError, err: err}
		}
		if _, err := fmt.Fprintln(deps.stdout, key); err != nil {
			fmt.Fprintf(deps.stderr, "Error writing output: %v\n", err)
			return &exitError{code: ExitIOError, err: err}
		}
		return nil
	}

	// Execution Flow: Key Generation (32-char printable Base64URL raw key)
	if *generateRawFlag {
		key, err := deps.generateRawKey()
		if err != nil {
			fmt.Fprintf(deps.stderr, "Error generating raw key: %v\n", err)
			return &exitError{code: ExitCryptoError, err: err}
		}
		if _, err := fmt.Fprintln(deps.stdout, key); err != nil {
			fmt.Fprintf(deps.stderr, "Error writing output: %v\n", err)
			return &exitError{code: ExitIOError, err: err}
		}
		return nil
	}

	// Explicit -key-file takes priority over the ambient default environment variable
	// unless the user also passed -key-env explicitly.
	keyEnv := *keyEnvFlag
	if !visited["key-env"] && *keyFileFlag != "" {
		keyEnv = ""
	}

	// Execution Flow: Encryption
	if encryptSet {
		var plainBytes []byte
		if *encryptFlag == "-" {
			inputBytes, err := readBoundedCLI(deps.stdin, maxStdinSecretBytes)
			if err != nil {
				fmt.Fprintf(deps.stderr, "Error reading stdin: %v\n", err)
				return &exitError{code: ExitIOError, err: err}
			}
			plainBytes = trimSingleLineEnding(inputBytes)
			defer libsecsecrets.ZeroBuffer(inputBytes)
		} else {
			plainBytes = []byte(*encryptFlag)
		}
		defer libsecsecrets.ZeroBuffer(plainBytes)

		key, err := resolveCLIKey(ctx, deps, *keyFlag, keyEnv, *keyFileFlag)
		if err != nil {
			return err
		}
		defer libsecsecrets.ZeroBuffer(key)

		encrypted, err := deps.encryptBytes(ctx, plainBytes, key)
		if err != nil {
			fmt.Fprintf(deps.stderr, "Error encrypting: %v\n", err)
			return &exitError{code: ExitCryptoError, err: err}
		}
		if _, err := fmt.Fprintf(deps.stdout, "%s\n", encrypted); err != nil {
			fmt.Fprintf(deps.stderr, "Error writing output: %v\n", err)
			return &exitError{code: ExitIOError, err: err}
		}
		return nil
	}

	// Execution Flow: Decryption
	var cipherBytes []byte
	if *decryptFlag == "-" {
		inputBytes, err := readBoundedCLI(deps.stdin, maxStdinSecretBytes)
		if err != nil {
			fmt.Fprintf(deps.stderr, "Error reading stdin: %v\n", err)
			return &exitError{code: ExitIOError, err: err}
		}
		defer libsecsecrets.ZeroBuffer(inputBytes)
		cipherBytes = bytes.TrimSpace(inputBytes)
	} else {
		cipherBytes = []byte(*decryptFlag)
	}

	key, err := resolveCLIKey(ctx, deps, *keyFlag, keyEnv, *keyFileFlag)
	if err != nil {
		return err
	}
	defer libsecsecrets.ZeroBuffer(key)

	decryptedBytes, err := deps.decryptBytes(ctx, cipherBytes, key)
	if err != nil {
		fmt.Fprintf(deps.stderr, "Error decrypting: %v\n", err)
		return &exitError{code: ExitCryptoError, err: err}
	}
	defer libsecsecrets.ZeroBuffer(decryptedBytes)

	if _, err := deps.stdout.Write(decryptedBytes); err != nil {
		fmt.Fprintf(deps.stderr, "Error writing output: %v\n", err)
		return &exitError{code: ExitIOError, err: err}
	}
	if !*rawFlag {
		if _, err := deps.stdout.Write([]byte("\n")); err != nil {
			fmt.Fprintf(deps.stderr, "Error writing output: %v\n", err)
			return &exitError{code: ExitIOError, err: err}
		}
	}
	return nil
}

// resolveCLIKey resolves the master key via injected deps and maps failures to diagnostic exit codes.
func resolveCLIKey(ctx context.Context, deps cliDeps, keyFlag, keyEnv, keyFile string) ([]byte, error) {
	key, err := deps.resolveKey(ctx, keyFlag, keyEnv, keyFile)
	if err != nil {
		fmt.Fprintf(deps.stderr, "Error resolving key: %v\n", err)
		return nil, &exitError{code: classifyKeyError(err), err: err}
	}
	return key, nil
}

// readBoundedCLI reads at most limit bytes from r, scrubbing partial data and returning an error if exceeded.
func readBoundedCLI(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		libsecsecrets.ZeroBuffer(data)
		return nil, err
	}
	if int64(len(data)) > limit {
		libsecsecrets.ZeroBuffer(data)
		return nil, fmt.Errorf("stdin payload exceeds maximum limit of %d bytes", limit)
	}
	return data, nil
}

// trimSingleLineEnding strips at most one trailing CRLF (\r\n) or LF (\n) line ending while preserving interior whitespace.
func trimSingleLineEnding(b []byte) []byte {
	if bytes.HasSuffix(b, []byte("\r\n")) {
		return b[:len(b)-2]
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}

// classifyKeyError maps key validation/permission failures to ExitKeyResolutionError and file/stream errors to ExitIOError.
func classifyKeyError(err error) int {
	if errors.Is(err, libsecsecrets.ErrNoKeySource) ||
		errors.Is(err, libsecsecrets.ErrInvalidKey) ||
		errors.Is(err, libsecsecrets.ErrInsecurePermissions) ||
		errors.Is(err, libsecsecrets.ErrInsecureLocation) {
		return ExitKeyResolutionError
	}
	return ExitIOError
}
