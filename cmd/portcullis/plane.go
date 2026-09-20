package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/clock"
	"github.com/nshekhawat/portcullis/internal/config"
	"github.com/nshekhawat/portcullis/internal/controller"
	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/judge/mock"
	"github.com/nshekhawat/portcullis/internal/judge/rules"
	"github.com/nshekhawat/portcullis/internal/judge/typesafe"
	"github.com/nshekhawat/portcullis/internal/metrics"
	"github.com/nshekhawat/portcullis/internal/netx"
	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/signals"
	"github.com/nshekhawat/portcullis/internal/storage"
)

// plane holds the judgment plane's running parts.
type plane struct {
	aggregator *signals.ShardedAggregator
	controller *controller.Controller
	tiers      policy.TierStore
	audit      *controller.AuditRing
	// recorder is nil when signals are disabled, so nothing records.
	recorder    signals.Recorder
	tierConfigs map[policy.Tier]policy.TierConfig
	guardrails  controller.Guardrails
	close       func()
}

// buildPlane assembles the signals, detection and judgment planes.
//
// Everything is optional: with judgment.mode off the services still run, they
// simply never consult a tier.
func buildPlane(ctx context.Context, cfg *config.Config, logger *zap.Logger) (*plane, error) {
	observer := metrics.NewControllerObserver(metrics.DefaultMetrics)

	tiers, closeTiers, tiersErr := buildTierStore(ctx, cfg, logger)
	if tiersErr != nil {
		return nil, tiersErr
	}

	aggregator := signals.NewShardedAggregator(signals.Options{
		Buffer:                  cfg.Signals.Buffer,
		Window:                  cfg.Signals.Window,
		MaxIdentities:           cfg.Signals.MaxIdentities,
		SampledPathsPerIdentity: cfg.Signals.SampledPathsPerIdentity,
		AggregatePrefixes:       cfg.Signals.AggregatePrefixes,
		Observer:                metrics.NewSignalsObserver(metrics.DefaultMetrics),
	})

	if !cfg.Signals.Enabled {
		logger.Warn("signals are disabled: the judgment plane will see no traffic")
	}

	tierConfigs, err := cfg.Judgment.TierConfigs()
	if err != nil {
		return nil, fmt.Errorf("invalid judgment tiers: %w", err)
	}

	guardrails, err := buildGuardrails(cfg.Judgment)
	if err != nil {
		return nil, err
	}

	primary, err := buildJudge(cfg, logger)
	if err != nil {
		return nil, err
	}
	fallback, err := buildFallbackJudge(cfg, logger)
	if err != nil {
		return nil, err
	}

	audit := controller.NewAuditRing(cfg.Judgment.Audit.RingSize)

	breaker := controller.NewBreaker(controller.BreakerOptions{
		Failures: cfg.Judgment.CircuitBreaker.Failures,
		OpenFor:  cfg.Judgment.CircuitBreaker.OpenFor,
		OnState: func(state controller.BreakerState) {
			observer.Observe(controller.Event{
				Kind: controller.EventBreakerState, Judge: primary.Name(), BreakerState: state,
			})
		},
	})

	detector := detect.NewDetector(detect.Options{
		MaxSuspects: cfg.Detection.MaxSuspects,
		MinScore:    cfg.Detection.MinScore,
		MinRequests: cfg.Detection.MinRequests,
		Allowlist:   cfg.Judgment.Guardrails.Allowlist,
		HardEvidence: detect.HardEvidenceOptions{
			RPSCeiling:      cfg.Detection.HardEvidence.RPSCeiling,
			AuthFailRatio:   cfg.Detection.HardEvidence.AuthFailRatio,
			ScannerPaths:    loadScannerPaths(cfg.Detection.HardEvidence.ScannerPathsFile, logger),
			MinAuthAttempts: 10,
		},
	})

	ctrl := controller.New(controller.Options{
		Mode:        controller.Mode(cfg.Judgment.Mode),
		Interval:    cfg.Detection.Interval,
		Judge:       primary,
		Fallback:    fallback,
		Timeout:     cfg.Judgment.Timeout,
		Detector:    detector,
		Aggregator:  aggregator,
		Tiers:       tiers,
		Policy:      &cfg.Judgment,
		TierConfigs: tierConfigs,
		Guardrails:  guardrails,
		Budget: controller.NewBudget(
			cfg.Judgment.Budget.MaxCallsPerMinute,
			cfg.Judgment.Budget.MaxInputTokensPerDay,
			clock.System(),
		),
		Breaker:  breaker,
		Audit:    audit,
		Observer: observer,
		Logger:   logger,
	})

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctrl.Run(runCtx)
	}()

	logger.Info("judgment plane configured",
		zap.String("mode", cfg.Judgment.Mode),
		zap.String("judge", primary.Name()),
		zap.String("fallback", judgeName(fallback)),
		zap.Duration("interval", cfg.Detection.Interval),
	)

	var recorder signals.Recorder
	if cfg.Signals.Enabled {
		recorder = aggregator
	}

	return &plane{
		aggregator:  aggregator,
		recorder:    recorder,
		controller:  ctrl,
		tiers:       tiers,
		audit:       audit,
		tierConfigs: tierConfigs,
		guardrails:  guardrails,
		close: func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				logger.Warn("controller did not stop within 5s")
			}
			aggregator.Close()
			if closeTiers != nil {
				closeTiers()
			}
		},
	}, nil
}

// buildTierStore creates the tier store, using Redis when the bucket backend is
// Redis so replicas share one tier table.
func buildTierStore(ctx context.Context, cfg *config.Config, logger *zap.Logger) (store policy.TierStore, closeFn func(), err error) {
	if cfg.Storage.Backend != config.BackendRedis {
		return policy.NewMemoryStore(clock.System()), nil, nil
	}

	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Redis.Address,
		Password:     cfg.Redis.Password,
		DB:           cfg.Redis.DB,
		PoolSize:     cfg.Redis.PoolSize,
		MinIdleConns: cfg.Redis.MinIdleConns,
		DialTimeout:  cfg.Redis.DialTimeout,
		ReadTimeout:  cfg.Redis.ReadTimeout,
		WriteTimeout: cfg.Redis.WriteTimeout,
		MaxRetries:   -1,
	})

	if pingErr := client.Ping(ctx).Err(); pingErr != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("failed to connect to Redis for the tier store: %w", pingErr)
	}

	redisStore, err := policy.NewRedisStore(ctx, client, policy.RedisOptions{
		ResyncInterval: 10 * time.Second,
		Clock:          clock.System(),
		Logger:         logger,
	})
	if err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("failed to start the Redis tier store: %w", err)
	}

	return redisStore, func() {
		_ = redisStore.Close()
		_ = client.Close()
	}, nil
}

// buildGuardrails parses the guardrail configuration.
//
//nolint:gocritic // called once at startup
func buildGuardrails(cfg config.JudgmentConfig) (controller.Guardrails, error) {
	g := cfg.Guardrails
	guardrails := controller.Guardrails{
		AllowlistIdentities:       map[string]bool{},
		BlockMinConfidence:        g.BlockMinConfidence,
		BlockRequiresHardEvidence: g.BlockRequiresHardEvidence,
		MaxNewBlocksPerCycle:      g.MaxNewBlocksPerCycle,
		MaxNonNormalFraction:      g.MaxNonNormalFraction,
		MaxTTL:                    g.MaxTTL,
		MinConfidenceToAct:        cfg.MinConfidence,
	}

	for _, entry := range g.Allowlist {
		prefixes, err := netx.ParsePrefixes([]string{entry})
		if err == nil && len(prefixes) == 1 && prefixes[0].Bits() != prefixes[0].Addr().BitLen() {
			guardrails.Allowlist = append(guardrails.Allowlist, prefixes[0])
			continue
		}
		if err == nil {
			// A bare address allowlists exactly that identity.
			guardrails.Allowlist = append(guardrails.Allowlist, prefixes[0])
			continue
		}
		// Anything that is not an address is an exact identity (an API key, a
		// service name, a prefix window).
		guardrails.AllowlistIdentities[entry] = true
	}

	return guardrails, nil
}

// buildJudge constructs the configured primary judge.
func buildJudge(cfg *config.Config, logger *zap.Logger) (judge.Judge, error) {
	switch cfg.Judgment.Judge {
	case config.JudgeRules:
		return rules.New(), nil

	case config.JudgeTypeSafe:
		apiKey := os.Getenv(cfg.Judgment.TypeSafe.APIKeyEnv)
		if apiKey == "" {
			logger.Warn("no API key set for the typesafe judge; falling back to the rules judge",
				zap.String("env", cfg.Judgment.TypeSafe.APIKeyEnv))
			return rules.New(), nil
		}
		return typesafe.New(typesafe.Options{
			BaseURL:          cfg.Judgment.TypeSafe.BaseURL,
			APIKey:           apiKey,
			Model:            cfg.Judgment.TypeSafe.Model,
			Timeout:          cfg.Judgment.Timeout,
			SendSampledPaths: cfg.Judgment.TypeSafe.SendSampledPaths,
		}), nil

	case config.JudgeMock:
		logger.Warn("the mock judge is for tests; it returns a fixed label")
		return mock.NewWithLabel(judge.LabelLegitimateBurst, 0.5), nil

	default:
		return nil, fmt.Errorf("unknown judge %q", cfg.Judgment.Judge)
	}
}

// buildFallbackJudge constructs the fallback judge, if one is configured.
func buildFallbackJudge(cfg *config.Config, logger *zap.Logger) (judge.Judge, error) {
	switch cfg.Judgment.FallbackJudge {
	case "":
		return nil, nil
	case config.JudgeRules:
		return rules.New(), nil
	case config.JudgeTypeSafe:
		apiKey := os.Getenv(cfg.Judgment.TypeSafe.APIKeyEnv)
		if apiKey == "" {
			return nil, nil
		}
		return typesafe.New(typesafe.Options{
			BaseURL: cfg.Judgment.TypeSafe.BaseURL,
			APIKey:  apiKey,
			Model:   cfg.Judgment.TypeSafe.Model,
			Timeout: cfg.Judgment.Timeout,
		}), nil
	case config.JudgeMock:
		logger.Warn("the mock judge is for tests; it returns a fixed label")
		return mock.NewWithLabel(judge.LabelLegitimateBurst, 0.5), nil
	default:
		return nil, fmt.Errorf("unknown fallback judge %q", cfg.Judgment.FallbackJudge)
	}
}

// loadScannerPaths reads an optional scanner-path override file, one path per
// line. Comments and blank lines are ignored.
func loadScannerPaths(path string, logger *zap.Logger) []string {
	if path == "" {
		return nil
	}

	//nolint:gosec // the path comes from the operator's configuration
	data, err := os.ReadFile(path)
	if err != nil {
		logger.Warn("failed to read scanner_paths_file; using the built-in list",
			zap.String("path", path), zap.Error(err))
		return nil
	}

	var paths []string
	for _, line := range splitLines(string(data)) {
		if line == "" || line[0] == '#' {
			continue
		}
		paths = append(paths, line)
	}
	if len(paths) == 0 {
		return nil
	}
	return paths
}

// splitLines splits on newlines, trimming spaces and carriage returns.
func splitLines(s string) []string {
	lines := make([]string, 0, 8)
	current := ""
	flush := func() {
		trimmed := ""
		for _, r := range current {
			if r == '\r' || r == ' ' || r == '\t' {
				continue
			}
			trimmed += string(r)
		}
		lines = append(lines, trimmed)
		current = ""
	}
	for _, r := range s {
		if r == '\n' {
			flush()
			continue
		}
		current += string(r)
	}
	flush()
	return lines
}

// judgeName renders a judge's name for logs.
func judgeName(j judge.Judge) string {
	if j == nil {
		return "none"
	}
	return j.Name()
}

// ruleNames returns the configured rule names for the metrics allowlist, sorted
// for determinism.
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

// buildLimiterConfig converts the configuration into a limiter config with the
// tier store attached.
func buildLimiterConfig(cfg *config.Config, p *plane) *ratelimiter.Config {
	limiterConfig := cfg.ToRateLimiterConfig()
	limiterConfig.OnStorageError = cfg.Storage.OnStorageError
	limiterConfig.Observer = metrics.NewDecisionRecorder(metrics.DefaultMetrics, ruleNames(cfg)...)
	if p != nil {
		limiterConfig.Tiers = p.tiers
		limiterConfig.TierConfigs = p.tierConfigs
	}
	return limiterConfig
}

// initStorage builds the configured backend. The backend is chosen by
// storage.backend; the pre-rename PORTCULLIS_USE_REDIS variable still works for
// one release (B17).
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
