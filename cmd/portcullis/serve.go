package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/nshekhawat/portcullis/internal/config"
	"github.com/nshekhawat/portcullis/internal/netx"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/server"
)

// runServe starts the HTTP and gRPC check APIs.
func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("CONFIG_PATH"), "path to the configuration file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	logger, err := initLogger(cfg.Logging)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer func() { _ = logger.Sync() }()

	config.LogDeprecationOnce(func() {
		for _, name := range cfg.Deprecations {
			logger.Warn("deprecated setting in use", zap.String("setting", name))
		}
	})

	logger.Info("starting portcullis service", zap.String("version", version), zap.String("commit", commit))

	store, err := initStorage(cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer func() { _ = store.Close() }()

	pingCtx, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelPing()
	if pingErr := store.Ping(pingCtx); pingErr != nil {
		return fmt.Errorf("storage ping failed: %w", pingErr)
	}
	logger.Info("storage connected successfully")

	trustedProxies, err := netx.ParsePrefixes(cfg.Server.TrustedProxies)
	if err != nil {
		return fmt.Errorf("invalid server.trusted_proxies: %w", err)
	}

	judgment, err := buildPlane(context.Background(), cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to build the judgment plane: %w", err)
	}
	defer judgment.close()

	limiter := ratelimiter.NewRateLimiter(store, buildLimiterConfig(cfg, judgment), logger)

	errCh := make(chan error, 2)

	httpServer := server.NewHTTPServer(limiter, store, &server.HTTPConfig{
		Port:              cfg.Server.HTTPPort,
		ReadTimeout:       cfg.Server.ReadTimeout,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		ShutdownTimeout:   cfg.Server.ShutdownTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
		MaxBodyBytes:      cfg.Server.MaxBodyBytes,
		MetricsPath:       cfg.Metrics.Path,
		MetricsEnabled:    cfg.Metrics.Enabled,
		TrustedProxies:    trustedProxies,
		AdminTokens:       cfg.Admin.Tokens(),
		CORSOrigins:       cfg.Server.CORSOrigins,
		Metrics:           metricsRegistry(),
		Tiers:             judgment.tiers,
		Audit:             judgment.audit,
		Mode:              judgment.controller,
		Signals:           judgment.recorder,
		TierConfigs:       judgment.tierConfigs,
		MaxTTL:            cfg.Judgment.Guardrails.MaxTTL,
	}, logger)

	go func() {
		if err := httpServer.Start(); err != nil {
			errCh <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	grpcServer := server.NewGRPCServer(limiter, &server.GRPCConfig{
		Port:              cfg.Server.GRPCPort,
		MaxRecvMsgSize:    4 * 1024 * 1024,
		MaxSendMsgSize:    4 * 1024 * 1024,
		EnableReflection:  cfg.Server.GRPCReflection,
		EnableHealthCheck: true,
		AdminTokens:       cfg.Admin.Tokens(),
		Metrics:           metricsRegistry(),
		Tiers:             judgment.tiers,
		Audit:             judgment.audit,
		Mode:              judgment.controller,
		Signals:           judgment.recorder,
		TierConfigs:       judgment.tierConfigs,
		MaxTTL:            cfg.Judgment.Guardrails.MaxTTL,
	}, logger)

	go func() {
		if err := grpcServer.Start(); err != nil {
			errCh <- fmt.Errorf("gRPC server error: %w", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		logger.Error("server error", zap.Error(err))
	case sig := <-quit:
		logger.Info("received shutdown signal", zap.String("signal", sig.String()))
	}

	logger.Info("shutting down servers...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", zap.Error(err))
	}

	grpcServer.Stop()

	logger.Info("servers stopped successfully")
	return nil
}

// initLogger builds the process logger from configuration.
func initLogger(cfg config.LoggingConfig) (*zap.Logger, error) {
	var level zapcore.Level
	if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
		level = zapcore.InfoLevel
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	zapConfig := zap.Config{
		Level:            zap.NewAtomicLevelAt(level),
		Development:      false,
		Encoding:         cfg.Format,
		EncoderConfig:    encoderConfig,
		OutputPaths:      []string{cfg.Output},
		ErrorOutputPaths: []string{"stderr"},
	}

	return zapConfig.Build()
}
