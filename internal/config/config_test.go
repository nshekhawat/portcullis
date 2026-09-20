package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/ratelimiter"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Server defaults
	assert.Equal(t, 8080, cfg.Server.HTTPPort)
	assert.Equal(t, 9090, cfg.Server.GRPCPort)
	assert.Equal(t, 10*time.Second, cfg.Server.ReadTimeout)
	assert.Equal(t, 10*time.Second, cfg.Server.WriteTimeout)
	assert.Equal(t, 30*time.Second, cfg.Server.ShutdownTimeout)

	// Redis defaults
	assert.Equal(t, "localhost:6379", cfg.Redis.Address)
	assert.Equal(t, "", cfg.Redis.Password)
	assert.Equal(t, 0, cfg.Redis.DB)
	assert.Equal(t, 10, cfg.Redis.PoolSize)
	assert.Equal(t, 5, cfg.Redis.MinIdleConns)
	assert.Equal(t, 3, cfg.Redis.MaxRetries)

	// Rate limit defaults
	assert.Equal(t, "pc:", cfg.RateLimit.KeyPrefix)
	assert.False(t, cfg.RateLimit.EnableBypass)
	assert.Len(t, cfg.RateLimit.DefaultRules, 1)
	assert.Equal(t, "default", cfg.RateLimit.DefaultRules[0].Name)
	assert.Equal(t, int64(100), cfg.RateLimit.DefaultRules[0].Capacity)

	// Metrics defaults
	assert.True(t, cfg.Metrics.Enabled)
	assert.Equal(t, "/metrics", cfg.Metrics.Path)

	// Logging defaults
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)
	assert.Equal(t, "stdout", cfg.Logging.Output)
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		modifier    func(*Config)
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid default config",
			modifier:    func(c *Config) {},
			expectError: false,
		},
		{
			name: "invalid HTTP port - zero",
			modifier: func(c *Config) {
				c.Server.HTTPPort = 0
			},
			expectError: true,
			errorMsg:    "invalid HTTP port",
		},
		{
			name: "invalid HTTP port - too high",
			modifier: func(c *Config) {
				c.Server.HTTPPort = 70000
			},
			expectError: true,
			errorMsg:    "invalid HTTP port",
		},
		{
			name: "invalid gRPC port",
			modifier: func(c *Config) {
				c.Server.GRPCPort = 0
			},
			expectError: true,
			errorMsg:    "invalid gRPC port",
		},
		{
			name: "same HTTP and gRPC ports",
			modifier: func(c *Config) {
				c.Server.HTTPPort = 8080
				c.Server.GRPCPort = 8080
			},
			expectError: true,
			errorMsg:    "HTTP and gRPC ports must be different",
		},
		{
			name: "empty Redis address",
			modifier: func(c *Config) {
				c.Redis.Address = ""
			},
			expectError: true,
			errorMsg:    "redis address is required",
		},
		{
			name: "invalid Redis pool size",
			modifier: func(c *Config) {
				c.Redis.PoolSize = 0
			},
			expectError: true,
			errorMsg:    "redis pool size must be at least 1",
		},
		{
			name: "empty key prefix",
			modifier: func(c *Config) {
				c.RateLimit.KeyPrefix = ""
			},
			expectError: true,
			errorMsg:    "rate limit key prefix is required",
		},
		{
			name: "invalid log level",
			modifier: func(c *Config) {
				c.Logging.Level = "invalid"
			},
			expectError: true,
			errorMsg:    "invalid log level",
		},
		{
			name: "invalid log format",
			modifier: func(c *Config) {
				c.Logging.Format = "xml"
			},
			expectError: true,
			errorMsg:    "invalid log format",
		},
		{
			name: "negative capacity in default rule",
			modifier: func(c *Config) {
				c.RateLimit.DefaultRules = []ratelimiter.Rule{
					{Name: "test", Capacity: -1, RefillRate: 1.0},
				}
			},
			expectError: true,
			errorMsg:    "capacity must be non-negative",
		},
		{
			name: "negative refill rate in custom rule",
			modifier: func(c *Config) {
				c.RateLimit.CustomRules = map[string]ratelimiter.Rule{
					"test": {Name: "test", Capacity: 10, RefillRate: -1.0},
				}
			},
			expectError: true,
			errorMsg:    "refill rate must be non-negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modifier(cfg)

			err := cfg.Validate()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLoad_FromFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  http_port: 8081
  grpc_port: 9091
  read_timeout: 15s
  write_timeout: 15s
  shutdown_timeout: 45s

redis:
  address: "redis.example.com:6379"
  password: "secret"
  db: 1
  pool_size: 20
  min_idle_conns: 10
  dial_timeout: 10s
  read_timeout: 5s
  write_timeout: 5s
  max_retries: 5

ratelimit:
  key_prefix: "custom:"
  enable_bypass: true
  bypass_headers:
    - "X-Bypass-Token"
  default_rules:
    - name: "custom-default"
      capacity: 200
      refill_rate: 20.0
      period: 2m
      burst_size: 40
  custom_rules:
    api_heavy:
      name: "api_heavy"
      capacity: 10
      refill_rate: 1.0
      period: 1m
      burst_size: 5
  ttl: 2h

metrics:
  enabled: true
  path: "/custom-metrics"

logging:
  level: "debug"
  format: "console"
  output: "stderr"
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(configPath)
	require.NoError(t, err)

	// Verify loaded values
	assert.Equal(t, 8081, cfg.Server.HTTPPort)
	assert.Equal(t, 9091, cfg.Server.GRPCPort)
	assert.Equal(t, 15*time.Second, cfg.Server.ReadTimeout)

	assert.Equal(t, "redis.example.com:6379", cfg.Redis.Address)
	assert.Equal(t, "secret", cfg.Redis.Password)
	assert.Equal(t, 1, cfg.Redis.DB)
	assert.Equal(t, 20, cfg.Redis.PoolSize)

	assert.Equal(t, "custom:", cfg.RateLimit.KeyPrefix)
	assert.True(t, cfg.RateLimit.EnableBypass)
	assert.Contains(t, cfg.RateLimit.BypassHeaders, "X-Bypass-Token")
	assert.Len(t, cfg.RateLimit.DefaultRules, 1)
	assert.Equal(t, "custom-default", cfg.RateLimit.DefaultRules[0].Name)
	assert.Equal(t, int64(200), cfg.RateLimit.DefaultRules[0].Capacity)

	assert.Equal(t, "/custom-metrics", cfg.Metrics.Path)
	assert.Equal(t, "debug", cfg.Logging.Level)
	assert.Equal(t, "console", cfg.Logging.Format)
}

func TestLoad_FromEnv(t *testing.T) {
	// Create a minimal config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  http_port: 8080
  grpc_port: 9090
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Set environment variables
	t.Setenv("PORTCULLIS_SERVER_HTTP_PORT", "8888")
	t.Setenv("PORTCULLIS_REDIS_ADDRESS", "env-redis:6379")

	cfg, err := Load(configPath)
	require.NoError(t, err)

	// Environment variables should override config file
	assert.Equal(t, 8888, cfg.Server.HTTPPort)
	assert.Equal(t, "env-redis:6379", cfg.Redis.Address)
	assert.Empty(t, cfg.Deprecations)
}

func TestLoad_LegacyEnvPrefixHonored(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("server:\n  http_port: 8080\n"), 0644))

	t.Setenv("RATE_LIMITER_SERVER_HTTP_PORT", "9999")

	cfg, err := Load(configPath)
	require.NoError(t, err)

	assert.Equal(t, 9999, cfg.Server.HTTPPort)
	assert.Contains(t, cfg.Deprecations, "RATE_LIMITER_SERVER_HTTP_PORT")
}

func TestLoad_CurrentEnvPrefixWins(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("server:\n  http_port: 8080\n"), 0644))

	t.Setenv("PORTCULLIS_SERVER_HTTP_PORT", "7777")
	t.Setenv("RATE_LIMITER_SERVER_HTTP_PORT", "9999")

	cfg, err := Load(configPath)
	require.NoError(t, err)

	assert.Equal(t, 7777, cfg.Server.HTTPPort)
	assert.Empty(t, cfg.Deprecations)
}

func TestLoad_InvalidFile(t *testing.T) {
	// Create an invalid config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	invalidContent := `
server:
  http_port: "not a number"
`

	err := os.WriteFile(configPath, []byte(invalidContent), 0644)
	require.NoError(t, err)

	_, err = Load(configPath)
	assert.Error(t, err)
}

func TestLoad_NonExistentFile(t *testing.T) {
	// When config file doesn't exist, should use defaults
	// We need to ensure no config.yaml exists in current or configs directory
	tmpDir := t.TempDir()
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	os.Chdir(tmpDir)

	cfg, err := Load("")
	require.NoError(t, err)

	// Should have default values
	assert.Equal(t, 8080, cfg.Server.HTTPPort)
}

func TestLoadFromViper(t *testing.T) {
	v := viper.New()
	v.Set("server.http_port", 8082)
	v.Set("server.grpc_port", 9092)
	v.Set("redis.address", "viper-redis:6379")
	v.Set("redis.pool_size", 15)
	v.Set("ratelimit.key_prefix", "viper:")
	v.Set("logging.level", "info")
	v.Set("logging.format", "json")

	cfg, err := LoadFromViper(v)
	require.NoError(t, err)

	assert.Equal(t, 8082, cfg.Server.HTTPPort)
	assert.Equal(t, 9092, cfg.Server.GRPCPort)
	assert.Equal(t, "viper-redis:6379", cfg.Redis.Address)
	assert.Equal(t, 15, cfg.Redis.PoolSize)
	assert.Equal(t, "viper:", cfg.RateLimit.KeyPrefix)
}

func TestConfig_GetDefaultRule(t *testing.T) {
	t.Run("with default rules", func(t *testing.T) {
		cfg := DefaultConfig()
		rule := cfg.GetDefaultRule()
		assert.NotNil(t, rule)
		assert.Equal(t, "default", rule.Name)
		assert.Equal(t, int64(100), rule.Capacity)
	})

	t.Run("without default rules", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.RateLimit.DefaultRules = nil
		rule := cfg.GetDefaultRule()
		assert.NotNil(t, rule)
		assert.Equal(t, "default", rule.Name)
	})
}

func TestConfig_GetCustomRule(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RateLimit.CustomRules = map[string]ratelimiter.Rule{
		"api_heavy": {
			Name:       "api_heavy",
			Capacity:   10,
			RefillRate: 1.0,
		},
	}

	t.Run("existing rule", func(t *testing.T) {
		rule := cfg.GetCustomRule("api_heavy")
		assert.NotNil(t, rule)
		assert.Equal(t, "api_heavy", rule.Name)
		assert.Equal(t, int64(10), rule.Capacity)
	})

	t.Run("non-existing rule", func(t *testing.T) {
		rule := cfg.GetCustomRule("nonexistent")
		assert.Nil(t, rule)
	})
}

func TestConfig_ToRateLimiterConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RateLimit.CustomRules = map[string]ratelimiter.Rule{
		"api_heavy": {
			Name:       "api_heavy",
			Capacity:   10,
			RefillRate: 1.0,
		},
	}
	cfg.RateLimit.EnableBypass = true
	cfg.RateLimit.BypassHeaders = []string{"X-Test"}

	rlConfig := cfg.ToRateLimiterConfig()

	assert.Equal(t, cfg.RateLimit.KeyPrefix, rlConfig.KeyPrefix)
	assert.NotNil(t, rlConfig.DefaultRule)
	assert.Equal(t, cfg.RateLimit.DefaultRules[0].Name, rlConfig.DefaultRule.Name)
	assert.True(t, rlConfig.EnableBypass)
	assert.Contains(t, rlConfig.BypassHeaders, "X-Test")
	assert.Len(t, rlConfig.CustomRules, 1)
	assert.NotNil(t, rlConfig.CustomRules["api_heavy"])
}
