package main

import "github.com/nshekhawat/portcullis/internal/metrics"

// metricsRegistry returns the process-wide metrics instance.
func metricsRegistry() *metrics.Metrics { return metrics.DefaultMetrics }
