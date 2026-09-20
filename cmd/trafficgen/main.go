// Command trafficgen drives the demo and end-to-end traffic shapes.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nshekhawat/portcullis/internal/trafficgen"
)

const usageText = `trafficgen sends the Portcullis demo traffic shapes.

Usage:
  trafficgen [flags]

Flags:
  -scenario <name>   users|burst|scraper|stuffing|scanner|flood|retrystorm|outage|mixed (default mixed)
  -target <url>      base URL to send requests to (required)
  -duration <dur>    how long to run, e.g. 120s (default 30s)
  -seed <n>          seed for the reproducible shape (default 1)
  -concurrency <n>   cap on in-flight requests (0 means unlimited)
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "trafficgen: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("trafficgen", flag.ContinueOnError)
	scenarioName := fs.String("scenario", string(trafficgen.Mixed), "traffic scenario to generate")
	target := fs.String("target", os.Getenv("TRAFFICGEN_TARGET"), "base URL to send requests to")
	duration := fs.Duration("duration", 30*time.Second, "how long to run")
	seed := fs.Int64("seed", 1, "seed for the reproducible traffic shape")
	concurrency := fs.Int("concurrency", 0, "cap on in-flight requests, 0 for unlimited")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprint(os.Stderr, usageText)
		return err
	}

	scenario, err := trafficgen.ParseScenario(*scenarioName)
	if err != nil {
		return fmt.Errorf("%w (choose one of %s)", err, scenarioList())
	}
	if *target == "" {
		return fmt.Errorf("-target is required (or set TRAFFICGEN_TARGET)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "trafficgen: scenario=%s target=%s duration=%s seed=%d\n",
		scenario, *target, *duration, *seed)

	result, err := trafficgen.Run(ctx, scenario, trafficgen.Options{
		Target:         *target,
		Duration:       *duration,
		Seed:           *seed,
		MaxConcurrency: *concurrency,
	})
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, result.Summary())
	return nil
}

// scenarioList renders the available scenarios.
func scenarioList() string {
	names := make([]string, 0, len(trafficgen.AllScenarios()))
	for _, s := range trafficgen.AllScenarios() {
		names = append(names, string(s))
	}
	return strings.Join(names, ", ")
}
