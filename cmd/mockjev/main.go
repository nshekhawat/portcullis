// Command mockjev is a standalone fake TypeSafe System One server, used by the
// demo and the end-to-end tests so they run with no API key.
//
// It speaks the same wire format as the real endpoint (spec §5.6): it validates
// the request shape, answers every Choice question with the offline rules judge,
// and spreads the probabilities the way a Choice answer is documented to look. It
// also injects the two things the demo needs to show: latency, and failures that
// can be switched on mid-run.
//
//	mockjev -addr :8099 -latency 120ms -jitter 60ms -fail-rate 0 -rate-limit-rpm 1200
//	curl -X POST localhost:8099/chaos -d '{"fail_rate":1}'   # start an outage
//	curl localhost:8099/healthz                             # current settings
//
// It logs method, path, status, and duration, and never a body: a body holds
// untrusted client-supplied paths.
//
// The fake itself lives in internal/mockjev, so the end-to-end tests can start it
// in-process; this command is its standalone front end.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/nshekhawat/portcullis/internal/mockjev"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stderr)
	stop()

	if err != nil {
		fmt.Fprintf(os.Stderr, "mockjev: %v\n", err)
		os.Exit(1)
	}
}

// run parses the flags and serves until ctx is done.
func run(ctx context.Context, args []string, stderr io.Writer) error {
	cfg, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}
	cfg.Logger = newLogger(stderr)

	srv, err := mockjev.New(cfg)
	if err != nil {
		return err
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Start() }()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// parseFlags parses the mockjev flags and checks them. The check is the
// library's: building a server is what validates a config, and run builds the
// real one.
func parseFlags(args []string, stderr io.Writer) (mockjev.Config, error) {
	fs := flag.NewFlagSet("mockjev", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := mockjev.DefaultConfig()
	fs.StringVar(&cfg.Addr, "addr", cfg.Addr, "address to listen on")
	fs.DurationVar(&cfg.Latency, "latency", cfg.Latency, "artificial latency added to every answer")
	fs.DurationVar(&cfg.Jitter, "jitter", cfg.Jitter, "uniform jitter applied around the latency")
	fs.Float64Var(&cfg.FailRate, "fail-rate", cfg.FailRate, "share of requests answered with status-on-fail, in [0, 1]")
	fs.IntVar(&cfg.StatusOnFail, "status-on-fail", cfg.StatusOnFail, "status returned for injected failures")
	fs.IntVar(&cfg.RateLimitRPM, "rate-limit-rpm", cfg.RateLimitRPM, "requests per minute before a 429 (0 disables the limit)")

	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, "mockjev - a fake TypeSafe System One server for the Portcullis demo\n\n"+
			"Usage:\n  mockjev [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return cfg, nil
		}
		return cfg, err
	}
	if _, err := mockjev.New(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// newLogger returns the command's logger, which the fake server writes its
// startup line and its request lines to.
func newLogger(stderr io.Writer) *zap.Logger {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	return zap.New(zapcore.NewCore(zapcore.NewConsoleEncoder(encoderConfig), zapcore.AddSync(stderr), zapcore.InfoLevel))
}
