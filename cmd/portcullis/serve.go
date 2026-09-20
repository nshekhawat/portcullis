package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/nshekhawat/portcullis/internal/config"
	"github.com/nshekhawat/portcullis/internal/metrics"
	"github.com/nshekhawat/portcullis/internal/netx"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/server"
	"github.com/nshekhawat/portcullis/internal/storage"
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

	limiterConfig := cfg.ToRateLimiterConfig()
	limiterConfig.OnStorageError = cfg.Storage.OnStorageError
	limiterConfig.Observer = metrics.NewDecisionRecorder(metrics.DefaultMetrics, ruleNames(cfg)...)

	limiter := ratelimiter.NewRateLimiter(store, limiterConfig, logger)

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
		Metrics:           metrics.DefaultMetrics,
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
		Metrics:           metrics.DefaultMetrics,
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

// ruleNames returns the configured rule names for the metrics allowlist,
// sorted for determinism.
func ruleNames(cfg *config.Config) []string {
	names := make([]string, 0, len(cfg.RateLimit.Rules)+1)
	if name := cfg.RateLimit.DefaultRule.Name; name != "" {
		names = append(names, name)
	}
	for name := range cfg.RateLimit.Rules {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

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

// initStorage builds the configured backend. The backend is chosen by
// storage.backend; the pre-rename PORTCULLIS_USE_REDIS variable still works
// for one release (B17).
func initStorage(cfg *config.Config, logger *zap.Logger) (storage.AtomicStorage, error) {
	backend := cfg.Storage.Backend
	if useRedisEnv() {
		logger.Warn("PORTCULLIS_USE_REDIS is deprecated; set storage.backend: redis instead")
		backend = config.BackendRedis
	}

	switch backend {
	case config.BackendRedis:
		logger.Info("initializing Redis storage", zap.String("address", cfg.Redis.Address))
		store, err := storage.NewRedisStorage(&storage.RedisConfig{
			Address:      cfg.Redis.Address,
			Password:     cfg.Redis.Password,
			DB:           cfg.Redis.DB,
			PoolSize:     cfg.Redis.PoolSize,
			MinIdleConns: cfg.Redis.MinIdleConns,
			DialTimeout:  cfg.Redis.DialTimeout,
			ReadTimeout:  cfg.Redis.ReadTimeout,
			WriteTimeout: cfg.Redis.WriteTimeout,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create Redis storage: %w", err)
		}
		return metrics.NewInstrumentedAtomicStorage(store, "redis", nil), nil

	case config.BackendMemory:
		logger.Info("initializing memory storage",
			zap.Duration("cleanup_interval", cfg.Memory.CleanupInterval),
			zap.Int("max_keys", cfg.Memory.MaxKeys),
		)
		store := storage.NewMemoryStorageWithOptions(storage.MemoryOptions{
			CleanupInterval: cfg.Memory.CleanupInterval,
			MaxKeys:         cfg.Memory.MaxKeys,
		})
		return metrics.NewInstrumentedAtomicStorage(store, "memory", nil), nil

	default:
		return nil, fmt.Errorf("unsupported storage backend %q", backend)
	}
}

// useRedisEnv reports whether the legacy Redis toggle is set.
func useRedisEnv() bool {
	return os.Getenv(config.EnvPrefix+"USE_REDIS") == "true" || os.Getenv("RATE_LIMITER_USE_REDIS") == "true"
}
