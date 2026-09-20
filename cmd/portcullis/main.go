// Package main provides the entry point for the Portcullis service.
package main

import (
	"fmt"
	"os"
)

// version and commit are stamped at build time with
// -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "none"
)

const usageText = `portcullis - deterministic rate limiting with a calibrated judgment plane

Usage:
  portcullis <command> [flags]

Commands:
  serve        Run the check API (HTTP + gRPC) service
  healthcheck  Probe the local /health endpoint (exit 0 on healthy)
  version      Print version information
  help         Print this message

Run "portcullis <command> -h" for command-specific flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "healthcheck":
		err = runHealthcheck(os.Args[2:])
	case "version":
		fmt.Printf("portcullis %s (commit %s)\n", version, commit)
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "portcullis: unknown command %q\n\n%s", os.Args[1], usageText)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "portcullis %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}
