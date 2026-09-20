// Package config provides configuration management for the rate limiter service.
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

// warnLegacyEnvOnce ensures the process logs the rename deprecation at most once.
var warnLegacyEnvOnce sync.Once

// Config holds the complete application configuration.
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Redis     RedisConfig     `mapstructure:"redis"`
	RateLimit RateLimitConfig `mapstructure:"ratelimit"`
	Metrics   MetricsConfig   `mapstructure:"metrics"`
	Logging   LoggingConfig   `mapstructure:"logging"`

	// Deprecations names legacy environment variables that were honored while
	// loading. Callers should surface these as warnings. Never set from config.
	Deprecations []string `mapstructure:"-"`
}

// ServerConfig holds HTTP and gRPC server configuration.
type ServerConfig struct {
	HTTPPort        int           `mapstructure:"http_port"`
	GRPCPort        int           `mapstructure:"grpc_port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
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
	KeyPrefix     string                      `mapstructure:"key_prefix"`
	EnableBypass  bool                        `mapstructure:"enable_bypass"`
	BypassHeaders []string                    `mapstructure:"bypass_headers"`
	DefaultRules  []ratelimiter.Rule          `mapstructure:"default_rules"`
	CustomRules   map[string]ratelimiter.Rule `mapstructure:"custom_rules"`
	TTL           time.Duration               `mapstructure:"ttl"`
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

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			HTTPPort:        8080,
			GRPCPort:        9090,
			ReadTimeout:     10 * time.Second,
			WriteTimeout:    10 * time.Second,
			ShutdownTimeout: 30 * time.Second,
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
			KeyPrefix:     "pc:",
			EnableBypass:  false,
			BypassHeaders: []string{},
			DefaultRules: []ratelimiter.Rule{
				{
					Name:       "default",
					Capacity:   100,
					RefillRate: 10.0,
					Period:     time.Minute,
					BurstSize:  20,
				},
			},
			CustomRules: make(map[string]ratelimiter.Rule),
			TTL:         time.Hour,
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

	// Parse configuration
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	config.Deprecations = deprecations

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
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

// LogDeprecationOnce emits fn at most once per process for legacy env usage.
// It exists so callers can funnel the rename warning through their logger
// without config depending on a logging implementation.
func LogDeprecationOnce(fn func()) {
	warnLegacyEnvOnce.Do(fn)
}

// LoadFromViper loads configuration from an existing viper instance.
func LoadFromViper(v *viper.Viper) (*Config, error) {
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// setDefaults sets default values in viper.
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.http_port", 8080)
	v.SetDefault("server.grpc_port", 9090)
	v.SetDefault("server.read_timeout", "10s")
	v.SetDefault("server.write_timeout", "10s")
	v.SetDefault("server.shutdown_timeout", "30s")

	// Redis defaults
	v.SetDefault("redis.address", "localhost:6379")
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.pool_size", 10)
	v.SetDefault("redis.min_idle_conns", 5)
	v.SetDefault("redis.dial_timeout", "5s")
	v.SetDefault("redis.read_timeout", "3s")
	v.SetDefault("redis.write_timeout", "3s")
	v.SetDefault("redis.max_retries", 3)

	// Rate limit defaults
	v.SetDefault("ratelimit.key_prefix", "pc:")
	v.SetDefault("ratelimit.enable_bypass", false)
	v.SetDefault("ratelimit.ttl", "1h")

	// Metrics defaults
	v.SetDefault("metrics.enabled", true)
	v.SetDefault("metrics.path", "/metrics")

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	// Validate server config
	if c.Server.HTTPPort < 1 || c.Server.HTTPPort > 65535 {
		return fmt.Errorf("invalid HTTP port: %d", c.Server.HTTPPort)
	}
	if c.Server.GRPCPort < 1 || c.Server.GRPCPort > 65535 {
		return fmt.Errorf("invalid gRPC port: %d", c.Server.GRPCPort)
	}
	if c.Server.HTTPPort == c.Server.GRPCPort {
		return fmt.Errorf("HTTP and gRPC ports must be different")
	}

	// Validate Redis config
	if c.Redis.Address == "" {
		return fmt.Errorf("redis address is required")
	}
	if c.Redis.PoolSize < 1 {
		return fmt.Errorf("redis pool size must be at least 1")
	}

	// Validate rate limit config
	if c.RateLimit.KeyPrefix == "" {
		return fmt.Errorf("rate limit key prefix is required")
	}

	// Validate default rules
	for i, rule := range c.RateLimit.DefaultRules {
		if err := validateRule(&rule); err != nil {
			return fmt.Errorf("invalid default rule %d: %w", i, err)
		}
	}

	// Validate custom rules
	for name, rule := range c.RateLimit.CustomRules {
		if err := validateRule(&rule); err != nil {
			return fmt.Errorf("invalid custom rule '%s': %w", name, err)
		}
	}

	// Validate logging config
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[strings.ToLower(c.Logging.Level)] {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	validFormats := map[string]bool{"json": true, "console": true, "text": true}
	if !validFormats[strings.ToLower(c.Logging.Format)] {
		return fmt.Errorf("invalid log format: %s", c.Logging.Format)
	}

	return nil
}

// validateRule validates a single rate limit rule.
func validateRule(rule *ratelimiter.Rule) error {
	if rule.Capacity < 0 {
		return fmt.Errorf("capacity must be non-negative")
	}
	if rule.RefillRate < 0 {
		return fmt.Errorf("refill rate must be non-negative")
	}
	return nil
}

// GetDefaultRule returns the first default rule, or creates one if none exist.
func (c *Config) GetDefaultRule() *ratelimiter.Rule {
	if len(c.RateLimit.DefaultRules) > 0 {
		return &c.RateLimit.DefaultRules[0]
	}
	return &ratelimiter.Rule{
		Name:       "default",
		Capacity:   100,
		RefillRate: 10.0,
		Period:     time.Minute,
	}
}

// GetCustomRule returns a custom rule by name, or nil if not found.
func (c *Config) GetCustomRule(name string) *ratelimiter.Rule {
	if rule, ok := c.RateLimit.CustomRules[name]; ok {
		return &rule
	}
	return nil
}

// ToRateLimiterConfig converts the config to a RateLimiter config.
func (c *Config) ToRateLimiterConfig() *ratelimiter.Config {
	customRules := make(map[string]*ratelimiter.Rule)
	for name, rule := range c.RateLimit.CustomRules {
		ruleCopy := rule
		customRules[name] = &ruleCopy
	}

	return &ratelimiter.Config{
		KeyPrefix:     c.RateLimit.KeyPrefix,
		DefaultRule:   c.GetDefaultRule(),
		CustomRules:   customRules,
		EnableBypass:  c.RateLimit.EnableBypass,
		BypassHeaders: c.RateLimit.BypassHeaders,
		TTL:           c.RateLimit.TTL,
	}
}
