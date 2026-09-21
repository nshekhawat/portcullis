// Package config provides configuration management for the Portcullis service.
package config

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"

	"github.com/nshekhawat/portcullis/internal/ratelimiter"
)

// EnvPrefix is the environment variable prefix for all Portcullis settings.
const EnvPrefix = "PORTCULLIS_"

// legacyEnvPrefix is honored for one minor release after the rename from
// rate-limiter-go. A deprecation warning is recorded for every legacy variable
// that actually supplied a value.
const legacyEnvPrefix = "RATE_LIMITER_"

// Storage backends.
const (
	BackendMemory = "memory"
	BackendRedis  = "redis"
)

// Storage error policies.
const (
	OnStorageErrorDeny  = "deny"
	OnStorageErrorAllow = "allow"
)

// warnLegacyEnvOnce ensures the process logs the rename deprecation at most once.
var warnLegacyEnvOnce sync.Once

// Config holds the complete application configuration.
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Admin     AdminConfig     `mapstructure:"admin"`
	Storage   StorageConfig   `mapstructure:"storage"`
	Memory    MemoryConfig    `mapstructure:"memory"`
	Redis     RedisConfig     `mapstructure:"redis"`
	RateLimit RateLimitConfig `mapstructure:"ratelimit"`
	Metrics   MetricsConfig   `mapstructure:"metrics"`
	Logging   LoggingConfig   `mapstructure:"logging"`

	Gateway   GatewayConfig   `mapstructure:"gateway"`
	Signals   SignalsConfig   `mapstructure:"signals"`
	Detection DetectionConfig `mapstructure:"detection"`
	Judgment  JudgmentConfig  `mapstructure:"judgment"`

	// Deprecations names legacy environment variables and retired settings that
	// were honored while loading. Callers should surface these as warnings.
	// Never set from config.
	Deprecations []string `mapstructure:"-"`
}

// ServerConfig holds HTTP and gRPC server configuration.
type ServerConfig struct {
	HTTPPort int `mapstructure:"http_port"`
	GRPCPort int `mapstructure:"grpc_port"`

	ReadTimeout       time.Duration `mapstructure:"read_timeout"`
	ReadHeaderTimeout time.Duration `mapstructure:"read_header_timeout"`
	WriteTimeout      time.Duration `mapstructure:"write_timeout"`
	IdleTimeout       time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout   time.Duration `mapstructure:"shutdown_timeout"`

	MaxHeaderBytes int   `mapstructure:"max_header_bytes"`
	MaxBodyBytes   int64 `mapstructure:"max_body_bytes"`

	// TrustedProxies lists CIDRs whose X-Forwarded-For headers are believed.
	// Empty means trust nobody and use the peer address (B2).
	TrustedProxies []string `mapstructure:"trusted_proxies"`

	// CORSOrigins lists the browser origins allowed on public routes. Empty
	// emits no CORS headers at all; admin routes never receive them (B4).
	CORSOrigins []string `mapstructure:"cors_origins"`

	// GRPCReflection enables server reflection. Off by default: it exposes the
	// full API surface to anyone who can reach the port (B4).
	GRPCReflection bool `mapstructure:"grpc_reflection"`
}

// AdminConfig holds admin API authentication settings.
type AdminConfig struct {
	// TokensEnv names the environment variable holding comma-separated bearer
	// tokens. Tokens never live in YAML (B4).
	TokensEnv string `mapstructure:"tokens_env"`
}

// Tokens returns the configured admin bearer tokens.
func (a AdminConfig) Tokens() []string {
	return splitList(os.Getenv(a.TokensEnv))
}

// StorageConfig selects the storage backend and its failure policy.
type StorageConfig struct {
	// Backend is "memory" or "redis".
	Backend string `mapstructure:"backend"`

	// OnStorageError decides what happens when the backend fails on the request
	// path: "deny" (fail closed, the default for a security tool) or "allow".
	OnStorageError string `mapstructure:"on_storage_error"`
}

// MemoryConfig holds in-memory storage tuning.
type MemoryConfig struct {
	CleanupInterval time.Duration `mapstructure:"cleanup_interval"`
	MaxKeys         int           `mapstructure:"max_keys"`
}

// RedisConfig holds Redis connection configuration.
type RedisConfig struct {
	Address      string        `mapstructure:"address"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	PoolSize     int           `mapstructure:"pool_size"`
	MinIdleConns int           `mapstructure:"min_idle_conns"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	MaxRetries   int           `mapstructure:"max_retries"`
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	KeyPrefix   string                      `mapstructure:"key_prefix"`
	TTL         time.Duration               `mapstructure:"ttl"`
	DefaultRule ratelimiter.Rule            `mapstructure:"default_rule"`
	Rules       map[string]ratelimiter.Rule `mapstructure:"rules"`
	Bypass      BypassConfig                `mapstructure:"bypass"`
}

// BypassConfig configures the secret-gated rate limit bypass (B3).
type BypassConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	Header     string `mapstructure:"header"`
	SecretsEnv string `mapstructure:"secrets_env"`
}

// Secrets returns the configured bypass secrets. Without a secret the bypass
// header is ignored entirely.
func (b BypassConfig) Secrets() []string {
	return splitList(os.Getenv(b.SecretsEnv))
}

// MetricsConfig holds metrics configuration.
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

// LoggingConfig holds logging configuration.
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

// splitList splits a comma-separated value, trimming spaces and dropping empties.
func splitList(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			HTTPPort:          8080,
			GRPCPort:          9090,
			ReadTimeout:       10 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			ShutdownTimeout:   30 * time.Second,
			MaxHeaderBytes:    64 * 1024,
			MaxBodyBytes:      8 * 1024,
			TrustedProxies:    []string{},
			CORSOrigins:       []string{},
			GRPCReflection:    false,
		},
		Admin: AdminConfig{TokensEnv: "PORTCULLIS_ADMIN_TOKENS"},
		Storage: StorageConfig{
			Backend:        BackendMemory,
			OnStorageError: OnStorageErrorDeny,
		},
		Memory: MemoryConfig{
			CleanupInterval: time.Minute,
			MaxKeys:         1_000_000,
		},
		Redis: RedisConfig{
			Address:      "localhost:6379",
			Password:     "",
			DB:           0,
			PoolSize:     10,
			MinIdleConns: 5,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			MaxRetries:   3,
		},
		RateLimit: RateLimitConfig{
			KeyPrefix: "pc:",
			TTL:       time.Hour,
			DefaultRule: ratelimiter.Rule{
				Name:       "default",
				Capacity:   100,
				RefillRate: 100,
				Period:     time.Minute,
			},
			Rules: map[string]ratelimiter.Rule{
				"login": {Name: "login", Capacity: 10, RefillRate: 10, Period: time.Minute},
			},
			Bypass: BypassConfig{ //nolint:gosec // SecretsEnv holds an environment variable name, not a credential
				Enabled:    false,
				Header:     "X-Portcullis-Bypass",
				SecretsEnv: "PORTCULLIS_BYPASS_SECRETS",
			},
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Path:    "/metrics",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
		Gateway:   DefaultGatewayConfig(),
		Signals:   DefaultSignalsConfig(),
		Detection: DefaultDetectionConfig(),
		Judgment:  DefaultJudgmentConfig(),
	}
}

// Load loads configuration from a file and environment variables.
//
// Environment variables use the PORTCULLIS_ prefix. Legacy RATE_LIMITER_*
// variables are still honored for one minor release; when one is used it is
// recorded in Config.Deprecations.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Configure config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./configs")
		v.AddConfigPath("/etc/portcullis")
	}

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found, use defaults and env vars
	}

	// Bind environment variables for every known key, preferring the current
	// prefix and falling back to the legacy one.
	deprecations := bindEnv(v)
	deprecations = append(deprecations, retireLegacyRules(v)...)

	// Parse configuration
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	config.Deprecations = deprecations
	config.normalize()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// retireLegacyRules maps the retired list-shaped rule settings onto the single
// default rule and the rules map. It records a deprecation for each one used.
func retireLegacyRules(v *viper.Viper) []string {
	var deprecations []string

	if v.IsSet("ratelimit.default_rules") && !explicitlySet(v, "ratelimit.default_rule") {
		var rules []ratelimiter.Rule
		if err := v.UnmarshalKey("ratelimit.default_rules", &rules); err == nil && len(rules) > 0 {
			v.Set("ratelimit.default_rule", rules[0])
			deprecations = append(deprecations, "ratelimit.default_rules")
		}
	}

	if v.IsSet("ratelimit.custom_rules") && !explicitlySet(v, "ratelimit.rules") {
		custom := v.GetStringMap("ratelimit.custom_rules")
		if len(custom) > 0 {
			v.Set("ratelimit.rules", custom)
			deprecations = append(deprecations, "ratelimit.custom_rules")
		}
	}

	return deprecations
}

// explicitlySet reports whether a key was supplied by the config file or the
// environment, as opposed to merely having a default.
func explicitlySet(v *viper.Viper, key string) bool {
	if v.InConfig(key) {
		return true
	}
	suffix := strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
	for _, prefix := range []string{EnvPrefix, legacyEnvPrefix} {
		if _, ok := os.LookupEnv(prefix + suffix); ok {
			return true
		}
	}
	return false
}

// bindEnv binds each known configuration key to its current and legacy
// environment variable names. A legacy name is only reported once the current
// name is absent, i.e. when it actually supplied the value.
func bindEnv(v *viper.Viper) []string {
	var deprecations []string
	for _, key := range v.AllKeys() {
		suffix := strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
		current := EnvPrefix + suffix
		legacy := legacyEnvPrefix + suffix
		if err := v.BindEnv(key, current, legacy); err != nil {
			continue
		}
		if _, legacySet := os.LookupEnv(legacy); !legacySet {
			continue
		}
		if _, currentSet := os.LookupEnv(current); currentSet {
			continue
		}
		deprecations = append(deprecations, legacy)
	}
	return deprecations
}

// LogDeprecationOnce emits fn at most once per process for legacy settings.
// It exists so callers can funnel warnings through their logger without config
// depending on a logging implementation.
func LogDeprecationOnce(fn func()) {
	warnLegacyEnvOnce.Do(fn)
}

// LoadFromViper loads configuration from an existing viper instance. Keys the
// caller has not set keep their defaults.
func LoadFromViper(v *viper.Viper) (*Config, error) {
	config := *DefaultConfig()
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	config.normalize()

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// normalize fills in derived defaults that validation then checks, and records
// retired settings that were still honored.
func (c *Config) normalize() {
	c.normalizeGateway()
	c.normalizePlanes()
	if c.RateLimit.DefaultRule.BurstSize != 0 {
		c.Deprecations = append(c.Deprecations, "ratelimit.default_rule.burst_size")
	}
	c.RateLimit.DefaultRule.Normalize()

	for name, rule := range c.RateLimit.Rules {
		if rule.Name == "" {
			rule.Name = name
		}
		rule.Normalize()
		if rule.BurstSize != 0 {
			c.Deprecations = append(c.Deprecations, "ratelimit.rules."+name+".burst_size")
		}
		c.RateLimit.Rules[name] = rule
	}
}

// setDefaults sets default values in viper.
func setDefaults(v *viper.Viper) {
	def := DefaultConfig()

	// Server defaults
	v.SetDefault("server.http_port", def.Server.HTTPPort)
	v.SetDefault("server.grpc_port", def.Server.GRPCPort)
	v.SetDefault("server.read_timeout", def.Server.ReadTimeout.String())
	v.SetDefault("server.read_header_timeout", def.Server.ReadHeaderTimeout.String())
	v.SetDefault("server.write_timeout", def.Server.WriteTimeout.String())
	v.SetDefault("server.idle_timeout", def.Server.IdleTimeout.String())
	v.SetDefault("server.shutdown_timeout", def.Server.ShutdownTimeout.String())
	v.SetDefault("server.max_header_bytes", def.Server.MaxHeaderBytes)
	v.SetDefault("server.max_body_bytes", def.Server.MaxBodyBytes)
	v.SetDefault("server.grpc_reflection", def.Server.GRPCReflection)

	// Admin defaults
	v.SetDefault("admin.tokens_env", def.Admin.TokensEnv)

	// Storage defaults
	v.SetDefault("storage.backend", def.Storage.Backend)
	v.SetDefault("storage.on_storage_error", def.Storage.OnStorageError)

	// Memory defaults
	v.SetDefault("memory.cleanup_interval", def.Memory.CleanupInterval.String())
	v.SetDefault("memory.max_keys", def.Memory.MaxKeys)

	// Redis defaults
	v.SetDefault("redis.address", def.Redis.Address)
	v.SetDefault("redis.password", def.Redis.Password)
	v.SetDefault("redis.db", def.Redis.DB)
	v.SetDefault("redis.pool_size", def.Redis.PoolSize)
	v.SetDefault("redis.min_idle_conns", def.Redis.MinIdleConns)
	v.SetDefault("redis.dial_timeout", def.Redis.DialTimeout.String())
	v.SetDefault("redis.read_timeout", def.Redis.ReadTimeout.String())
	v.SetDefault("redis.write_timeout", def.Redis.WriteTimeout.String())
	v.SetDefault("redis.max_retries", def.Redis.MaxRetries)

	// Rate limit defaults
	v.SetDefault("ratelimit.key_prefix", def.RateLimit.KeyPrefix)
	v.SetDefault("ratelimit.ttl", def.RateLimit.TTL.String())
	v.SetDefault("ratelimit.default_rule", def.RateLimit.DefaultRule)

	// Bypass defaults
	v.SetDefault("ratelimit.bypass.enabled", def.RateLimit.Bypass.Enabled)
	v.SetDefault("ratelimit.bypass.header", def.RateLimit.Bypass.Header)
	v.SetDefault("ratelimit.bypass.secrets_env", def.RateLimit.Bypass.SecretsEnv)

	// Metrics defaults
	v.SetDefault("metrics.enabled", def.Metrics.Enabled)
	v.SetDefault("metrics.path", def.Metrics.Path)

	// Logging defaults
	v.SetDefault("logging.level", def.Logging.Level)
	v.SetDefault("logging.format", def.Logging.Format)
	v.SetDefault("logging.output", def.Logging.Output)

	// Gateway defaults
	setGatewayDefaults(v)

	// Signals, detection and judgment defaults
	setPlaneDefaults(v)
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.Server.HTTPPort < 1 || c.Server.HTTPPort > 65535 {
		return fmt.Errorf("invalid HTTP port: %d", c.Server.HTTPPort)
	}
	if c.Server.GRPCPort < 1 || c.Server.GRPCPort > 65535 {
		return fmt.Errorf("invalid gRPC port: %d", c.Server.GRPCPort)
	}
	if c.Server.HTTPPort == c.Server.GRPCPort {
		return fmt.Errorf("HTTP and gRPC ports must be different")
	}
	if c.Server.ReadHeaderTimeout <= 0 {
		return fmt.Errorf("server read_header_timeout must be positive")
	}
	if c.Server.IdleTimeout <= 0 {
		return fmt.Errorf("server idle_timeout must be positive")
	}
	if c.Server.ShutdownTimeout <= 0 {
		return fmt.Errorf("server shutdown_timeout must be positive")
	}
	if c.Server.MaxHeaderBytes <= 0 {
		return fmt.Errorf("server max_header_bytes must be positive")
	}
	if c.Server.MaxBodyBytes <= 0 {
		return fmt.Errorf("server max_body_bytes must be positive")
	}
	for _, cidr := range c.Server.TrustedProxies {
		if strings.TrimSpace(cidr) == "" {
			return fmt.Errorf("server trusted_proxies contains an empty entry")
		}
	}
	for _, origin := range c.Server.CORSOrigins {
		if !strings.Contains(origin, "://") {
			return fmt.Errorf("server cors_origins entry %q must include a scheme", origin)
		}
	}

	switch c.Storage.Backend {
	case BackendMemory, BackendRedis:
	default:
		return fmt.Errorf("invalid storage backend %q (want %q or %q)",
			c.Storage.Backend, BackendMemory, BackendRedis)
	}
	switch c.Storage.OnStorageError {
	case OnStorageErrorDeny, OnStorageErrorAllow:
	default:
		return fmt.Errorf("invalid on_storage_error %q (want %q or %q)",
			c.Storage.OnStorageError, OnStorageErrorDeny, OnStorageErrorAllow)
	}

	if c.Memory.CleanupInterval <= 0 {
		return fmt.Errorf("memory cleanup_interval must be positive")
	}
	if c.Memory.MaxKeys < 1 {
		return fmt.Errorf("memory max_keys must be at least 1")
	}

	if c.Redis.Address == "" {
		return fmt.Errorf("redis address is required")
	}
	if c.Redis.PoolSize < 1 {
		return fmt.Errorf("redis pool size must be at least 1")
	}

	if c.RateLimit.KeyPrefix == "" {
		return fmt.Errorf("rate limit key prefix is required")
	}
	if c.RateLimit.TTL <= 0 {
		return fmt.Errorf("rate limit ttl must be positive")
	}
	if err := validateRule("default_rule", &c.RateLimit.DefaultRule); err != nil {
		return err
	}
	for name, rule := range c.RateLimit.Rules {
		if err := validateRule(fmt.Sprintf("rule %q", name), &rule); err != nil {
			return err
		}
	}
	if c.RateLimit.Bypass.Enabled {
		if strings.TrimSpace(c.RateLimit.Bypass.Header) == "" {
			return fmt.Errorf("ratelimit bypass header is required when bypass is enabled")
		}
		if strings.TrimSpace(c.RateLimit.Bypass.SecretsEnv) == "" {
			return fmt.Errorf("ratelimit bypass secrets_env is required when bypass is enabled")
		}
	}

	if !map[string]bool{"debug": true, "info": true, "warn": true, "error": true}[strings.ToLower(c.Logging.Level)] {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}
	if !map[string]bool{"json": true, "console": true, "text": true}[strings.ToLower(c.Logging.Format)] {
		return fmt.Errorf("invalid log format: %s", c.Logging.Format)
	}

	if err := c.validateGateway(); err != nil {
		return err
	}
	return c.validatePlanes()
}

// validateRule validates a single rate limit rule.
func validateRule(label string, rule *ratelimiter.Rule) error {
	if rule.Capacity < 1 {
		return fmt.Errorf("%s: capacity must be at least 1", label)
	}
	if rule.RefillRate <= 0 {
		return fmt.Errorf("%s: refill_rate must be positive", label)
	}
	if rule.Period <= 0 {
		return fmt.Errorf("%s: period must be positive", label)
	}
	if rule.BurstSize != 0 && rule.BurstSize != rule.Capacity {
		return fmt.Errorf("%s: burst_size is deprecated and must equal capacity (%d) when set",
			label, rule.Capacity)
	}
	return nil
}

// GetDefaultRule returns the default rule.
func (c *Config) GetDefaultRule() *ratelimiter.Rule {
	rule := c.RateLimit.DefaultRule
	if rule.Capacity == 0 {
		def := DefaultConfig().RateLimit.DefaultRule
		return &def
	}
	rule.Normalize()
	return &rule
}

// GetCustomRule returns a rule by name, or nil if not found. Lookup is
// case-insensitive because viper lowercases map keys (B22).
func (c *Config) GetCustomRule(name string) *ratelimiter.Rule {
	if name == "" {
		return nil
	}
	rule, ok := c.RateLimit.Rules[strings.ToLower(name)]
	if !ok {
		return nil
	}
	rule.Normalize()
	return &rule
}

// ToRateLimiterConfig converts the config to a RateLimiter config.
func (c *Config) ToRateLimiterConfig() *ratelimiter.Config {
	rules := make(map[string]*ratelimiter.Rule, len(c.RateLimit.Rules))
	for name, rule := range c.RateLimit.Rules {
		if rule.Name == "" {
			rule.Name = name
		}
		rule.Normalize()
		rules[strings.ToLower(name)] = &rule
	}

	return &ratelimiter.Config{
		KeyPrefix:   c.RateLimit.KeyPrefix,
		DefaultRule: c.GetDefaultRule(),
		Rules:       rules,
		TTL:         c.RateLimit.TTL,
	}
}
