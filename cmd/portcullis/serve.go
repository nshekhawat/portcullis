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
	"github.com/nshekhawat/portcullis/internal/metrics"
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
			logger.Warn("deprecated environment variable used; switch to the PORTCULLIS_ prefix",
				zap.String("legacy", name),
			)
		}
	})

	logger.Info("starting portcullis service", zap.String("version", version), zap.String("commit", commit))

	store, err := initStorage(cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer func() { _ = store.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.Ping(ctx); err != nil {
		return fmt.Errorf("storage ping failed: %w", err)
	}
	logger.Info("storage connected successfully")

	limiter := ratelimiter.NewRateLimiter(store, cfg.ToRateLimiterConfig(), logger)

	errCh := make(chan error, 2)

	httpServer := server.NewHTTPServer(limiter, &server.HTTPConfig{
		Port:           cfg.Server.HTTPPort,
		ReadTimeout:    cfg.Server.ReadTimeout,
		WriteTimeout:   cfg.Server.WriteTimeout,
		MetricsEnabled: cfg.Metrics.Enabled,
		MetricsPath:    cfg.Metrics.Path,
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
		EnableReflection:  true,
		EnableHealthCheck: true,
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

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", zap.Error(err))
	}

	grpcServer.Stop()

	logger.Info("servers stopped successfully")
	return nil
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

func initStorage(cfg *config.Config, logger *zap.Logger) (storage.AtomicStorage, error) {
	useRedis := os.Getenv("PORTCULLIS_USE_REDIS") == "true" || os.Getenv("RATE_LIMITER_USE_REDIS") == "true"

	if useRedis {
		logger.Info("initializing Redis storage", zap.String("address", cfg.Redis.Address))
		redisConfig := &storage.RedisConfig{
			Address:      cfg.Redis.Address,
			Password:     cfg.Redis.Password,
			DB:           cfg.Redis.DB,
			PoolSize:     cfg.Redis.PoolSize,
			MinIdleConns: cfg.Redis.MinIdleConns,
			DialTimeout:  cfg.Redis.DialTimeout,
			ReadTimeout:  cfg.Redis.ReadTimeout,
			WriteTimeout: cfg.Redis.WriteTimeout,
			MaxRetries:   cfg.Redis.MaxRetries,
		}
		store, err := storage.NewRedisStorage(redisConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create Redis storage: %w", err)
		}
		return metrics.NewInstrumentedAtomicStorage(store, "redis", nil), nil
	}

	logger.Info("initializing memory storage")
	store := storage.NewMemoryStorage(cfg.RateLimit.TTL)
	return metrics.NewInstrumentedAtomicStorage(store, "memory", nil), nil
}
