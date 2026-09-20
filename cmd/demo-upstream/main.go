// Command demo-upstream serves the toy application the demo stack protects.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nshekhawat/portcullis/internal/demoupstream"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "demo-upstream: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("demo-upstream", flag.ContinueOnError)
	addr := fs.String("addr", ":3000", "address to listen on")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	server := &http.Server{
		Addr:              *addr,
		Handler:           demoupstream.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       time.Minute,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "demo-upstream listening on %s\n", *addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}
