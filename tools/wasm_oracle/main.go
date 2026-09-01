package main

import (
	"context"
	"io"
	"os"
)

type commandArgs struct{ wasmPath, fixturePath, command string }

func parseArgs(args []string) (commandArgs, error) {
	var result commandArgs
	for len(args) > 0 && args[0] != "verify-fixtures" && args[0] != "validate-fixtures" {
		if len(args) < 2 {
			return result, fail("arguments")
		}
		switch args[0] {
		case "--wasm":
			result.wasmPath = args[1]
		case "--fixtures":
			result.fixturePath = args[1]
		default:
			return result, fail("arguments")
		}
		args = args[2:]
	}
	if len(args) != 1 || result.fixturePath == "" {
		return result, fail("arguments")
	}
	result.command = args[0]
	switch result.command {
	case "verify-fixtures":
		if result.wasmPath == "" {
			return result, fail("arguments")
		}
	case "validate-fixtures":
		if result.wasmPath != "" {
			return result, fail("arguments")
		}
	default:
		return result, fail("arguments")
	}
	return result, nil
}
func run(ctx context.Context, args []string, out io.Writer) int {
	parsed, err := parseArgs(args)
	if err != nil {
		emitStatus(out, statusLine{"verify-fixtures", "unavailable", "FAIL", categoryOf(err)})
		return 2
	}
	fixtures, err := validateFixtureSet(parsed.fixturePath, pinnedPolicy())
	if err != nil {
		emitStatus(out, statusLine{parsed.command, "unavailable", "FAIL", categoryOf(err)})
		return 1
	}
	if parsed.command == "validate-fixtures" {
		emitStatus(out, statusLine{"validate-fixtures", "static", "PASS", ""})
		return 0
	}
	source, err := readBoundedRegularFile(parsed.wasmPath, pinnedWASMSize, "wasm-read")
	if err == nil {
		err = validateWASM(source)
	}
	if err != nil {
		emitStatus(out, statusLine{"verify-fixtures", "unavailable", "FAIL", categoryOf(err)})
		return 1
	}
	if _, err = verifyFixtures(ctx, source, fixtures, out); err != nil {
		emitStatus(out, statusLine{"verify-fixtures", "unavailable", "FAIL", categoryOf(err)})
		return 1
	}
	return 0
}
func guarded(out io.Writer, action func() int) (status int) {
	defer func() {
		if recover() != nil {
			emitStatus(out, statusLine{"verify-fixtures", "unavailable", "FAIL", "internal"})
			status = 1
		}
	}()
	return action()
}

func main() {
	os.Exit(guarded(os.Stdout, func() int {
		return run(context.Background(), os.Args[1:], os.Stdout)
	}))
}
