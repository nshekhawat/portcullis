package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/gin-gonic/gin"

	"github.com/nshekhawat/portcullis/internal/config"
	"github.com/nshekhawat/portcullis/internal/gateway"
	"github.com/nshekhawat/portcullis/internal/netx"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/server"
	"github.com/nshekhawat/portcullis/internal/storage"
)

// runGateway starts the reverse-proxy gateway.
func runGateway(args []string) error {
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("CONFIG_PATH"), "path to the configuration file")
	listen := fs.String("listen", "", "address to proxy on, e.g. :8000")
	adminListen := fs.String("admin-listen", "", "address for health and admin endpoints, e.g. :8081")
	upstream := fs.String("upstream", "", "upstream application, e.g. http://app:3000")
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
	applyGatewayOverrides(&cfg.Gateway, *listen, *adminListen, *upstream)

	if validateErr := cfg.Validate(); validateErr != nil {
		return fmt.Errorf("invalid configuration: %w", validateErr)
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

	if cfg.Gateway.Upstream == "" {
		return errors.New("gateway needs an upstream: pass --upstream or set gateway.upstream")
	}

	logger.Info("starting portcullis gateway",
		zap.String("version", version), zap.String("commit", commit),
		zap.String("upstream", cfg.Gateway.Upstream))

	store, err := initStorage(cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer func() { _ = store.Close() }()

	trustedProxies, err := netx.ParsePrefixes(cfg.Server.TrustedProxies)
	if err != nil {
		return fmt.Errorf("invalid server.trusted_proxies: %w", err)
	}

	judgment, planeErr := buildPlane(context.Background(), cfg, logger)
	if planeErr != nil {
		return fmt.Errorf("failed to build the judgment plane: %w", planeErr)
	}
	defer judgment.close()

	limiter := ratelimiter.NewRateLimiter(store, buildLimiterConfig(cfg, judgment), logger)

	gw, err := gateway.New(limiter, gateway.Config{
		Listen:            cfg.Gateway.Listen,
		AdminListen:       cfg.Gateway.AdminListen,
		Upstream:          cfg.Gateway.Upstream,
		ReadTimeout:       cfg.Server.ReadTimeout,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		ShutdownTimeout:   cfg.Gateway.ShutdownTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
		MaxBodyBytes:      cfg.Gateway.MaxBodyBytes,
		TrustedProxies:    trustedProxies,
		AdminTokens:       cfg.Admin.Tokens(),
		MetricsEnabled:    cfg.Metrics.Enabled,
		MetricsPath:       cfg.Metrics.Path,
		Metrics:           metricsRegistry(),
		Signals:           judgment.recorder,
		IdentifierHeader:  cfg.Gateway.IdentifierHeader,
		APIKeyHeader:      cfg.Gateway.APIKeyHeader,
		Routes:            gatewayRoutes(cfg.Gateway.Routes),
		RegisterAdmin:     adminRouter(limiter, store, cfg, judgment, trustedProxies, logger),
	}, logger)
	if err != nil {
		return fmt.Errorf("failed to start the gateway: %w", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- gw.Start() }()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
	case sig := <-quit:
		logger.Info("received shutdown signal", zap.String("signal", sig.String()))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Gateway.ShutdownTimeout)
	defer cancel()
	if err := gw.Shutdown(shutdownCtx); err != nil {
		logger.Error("gateway shutdown error", zap.Error(err))
	}

	logger.Info("gateway stopped")
	return nil
}

// applyGatewayOverrides lets flags win over configuration.
func applyGatewayOverrides(cfg *config.GatewayConfig, listen, adminListen, upstream string) {
	if listen != "" {
		cfg.Listen = listen
	}
	if adminListen != "" {
		cfg.AdminListen = adminListen
	}
	if upstream != "" {
		cfg.Upstream = upstream
	}
}

// gatewayRoutes converts configured routes into gateway routes.
func gatewayRoutes(routes []config.GatewayRoute) []gateway.Route {
	out := make([]gateway.Route, 0, len(routes))
	for _, route := range routes {
		out = append(out, gateway.Route{Prefix: route.Prefix, Rule: route.Rule})
	}
	return out
}

// adminRouter mounts the full admin API on the gateway's admin listener.
//
// It builds an HTTPServer only to reuse its admin handlers; that server is never
// started, so its own listener is inert. Sharing the handlers keeps the two
// modes from drifting apart.
func adminRouter(
	limiter *ratelimiter.RateLimiter,
	store storage.AtomicStorage,
	cfg *config.Config,
	judgment *plane,
	trustedProxies []netip.Prefix,
	logger *zap.Logger,
) func(gin.IRouter) {
	admin := server.NewHTTPServer(limiter, store, &server.HTTPConfig{
		Port:           cfg.Server.HTTPPort,
		MetricsEnabled: false,
		TrustedProxies: trustedProxies,
		AdminTokens:    cfg.Admin.Tokens(),
		CORSOrigins:    cfg.Server.CORSOrigins,
		Metrics:        metricsRegistry(),
		Tiers:          judgment.tiers,
		Audit:          judgment.audit,
		Mode:           judgment.controller,
		Signals:        judgment.recorder,
		TierConfigs:    judgment.tierConfigs,
		MaxTTL:         cfg.Judgment.Guardrails.MaxTTL,
	}, logger)

	return admin.RegisterAdminRoutes
}
