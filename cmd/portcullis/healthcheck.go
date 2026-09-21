package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

// runHealthcheck probes a Portcullis /health endpoint and exits 0 when healthy.
//
// It exists so the container HEALTHCHECK works on distroless images, where no
// shell or wget is available.
func runHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:8080/health", "health endpoint URL")
	timeout := fs.Duration("timeout", 3*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	client := &http.Client{Timeout: *timeout}
	resp, err := client.Get(*url)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	_, _ = fmt.Fprintln(os.Stdout, "ok")
	return nil
}
