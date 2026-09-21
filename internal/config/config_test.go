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

	assert.Equal(t, 8080, cfg.Server.HTTPPort)
	assert.Equal(t, 9090, cfg.Server.GRPCPort)
	assert.Equal(t, 5*time.Second, cfg.Server.ReadHeaderTimeout)
	assert.Equal(t, 60*time.Second, cfg.Server.IdleTimeout)
	assert.Equal(t, 30*time.Second, cfg.Server.ShutdownTimeout)
	assert.Equal(t, 64*1024, cfg.Server.MaxHeaderBytes)
	assert.Equal(t, int64(8*1024), cfg.Server.MaxBodyBytes)
	assert.Empty(t, cfg.Server.TrustedProxies)
	assert.False(t, cfg.Server.GRPCReflection)

	assert.Equal(t, "PORTCULLIS_ADMIN_TOKENS", cfg.Admin.TokensEnv)
	assert.Equal(t, BackendMemory, cfg.Storage.Backend)
	assert.Equal(t, OnStorageErrorDeny, cfg.Storage.OnStorageError)
	assert.Equal(t, time.Minute, cfg.Memory.CleanupInterval)
	assert.Equal(t, 1_000_000, cfg.Memory.MaxKeys)

	assert.Equal(t, "localhost:6379", cfg.Redis.Address)
	assert.Equal(t, 10, cfg.Redis.PoolSize)

	assert.Equal(t, "pc:", cfg.RateLimit.KeyPrefix)
	assert.Equal(t, time.Hour, cfg.RateLimit.TTL)
	assert.Equal(t, "default", cfg.RateLimit.DefaultRule.Name)
	assert.Equal(t, int64(100), cfg.RateLimit.DefaultRule.Capacity)
	assert.Equal(t, 100.0, cfg.RateLimit.DefaultRule.RefillRate)
	assert.Equal(t, time.Minute, cfg.RateLimit.DefaultRule.Period)
	assert.Contains(t, cfg.RateLimit.Rules, "login")
	assert.False(t, cfg.RateLimit.Bypass.Enabled)
	assert.Equal(t, "X-Portcullis-Bypass", cfg.RateLimit.Bypass.Header)
	assert.Equal(t, "PORTCULLIS_BYPASS_SECRETS", cfg.RateLimit.Bypass.SecretsEnv)

	assert.True(t, cfg.Metrics.Enabled)
	assert.Equal(t, "/metrics", cfg.Metrics.Path)

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
			name:     "valid default config",
			modifier: func(*Config) {},
		},
		{
			name:        "invalid HTTP port",
			modifier:    func(c *Config) { c.Server.HTTPPort = 0 },
			expectError: true,
			errorMsg:    "invalid HTTP port",
		},
		{
			name:        "invalid gRPC port",
			modifier:    func(c *Config) { c.Server.GRPCPort = 70000 },
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
			errorMsg:    "must be different",
		},
		{
			name:        "zero read header timeout",
			modifier:    func(c *Config) { c.Server.ReadHeaderTimeout = 0 },
			expectError: true,
			errorMsg:    "read_header_timeout",
		},
		{
			name:        "zero idle timeout",
			modifier:    func(c *Config) { c.Server.IdleTimeout = 0 },
			expectError: true,
			errorMsg:    "idle_timeout",
		},
		{
			name:        "zero shutdown timeout",
			modifier:    func(c *Config) { c.Server.ShutdownTimeout = 0 },
			expectError: true,
			errorMsg:    "shutdown_timeout",
		},
		{
			name:        "non-positive max header bytes",
			modifier:    func(c *Config) { c.Server.MaxHeaderBytes = 0 },
			expectError: true,
			errorMsg:    "max_header_bytes",
		},
		{
			name:        "non-positive max body bytes",
			modifier:    func(c *Config) { c.Server.MaxBodyBytes = 0 },
			expectError: true,
			errorMsg:    "max_body_bytes",
		},
		{
			name:        "blank trusted proxy entry",
			modifier:    func(c *Config) { c.Server.TrustedProxies = []string{"  "} },
			expectError: true,
			errorMsg:    "trusted_proxies",
		},
		{
			name:        "CORS origin without scheme",
			modifier:    func(c *Config) { c.Server.CORSOrigins = []string{"example.com"} },
			expectError: true,
			errorMsg:    "cors_origins",
		},
		{
			name:        "unknown storage backend",
			modifier:    func(c *Config) { c.Storage.Backend = "sqlite" },
			expectError: true,
			errorMsg:    "invalid storage backend",
		},
		{
			name:        "unknown storage error policy",
			modifier:    func(c *Config) { c.Storage.OnStorageError = "maybe" },
			expectError: true,
			errorMsg:    "invalid on_storage_error",
		},
		{
			name:        "zero cleanup interval",
			modifier:    func(c *Config) { c.Memory.CleanupInterval = 0 },
			expectError: true,
			errorMsg:    "cleanup_interval",
		},
		{
			name:        "zero max keys",
			modifier:    func(c *Config) { c.Memory.MaxKeys = 0 },
			expectError: true,
			errorMsg:    "max_keys",
		},
		{
			name:        "empty redis address",
			modifier:    func(c *Config) { c.Redis.Address = "" },
			expectError: true,
			errorMsg:    "redis address is required",
		},
		{
			name:        "invalid redis pool size",
			modifier:    func(c *Config) { c.Redis.PoolSize = 0 },
			expectError: true,
			errorMsg:    "redis pool size",
		},
		{
			name:        "empty key prefix",
			modifier:    func(c *Config) { c.RateLimit.KeyPrefix = "" },
			expectError: true,
			errorMsg:    "key prefix is required",
		},
		{
			name:        "non-positive ttl",
			modifier:    func(c *Config) { c.RateLimit.TTL = 0 },
			expectError: true,
			errorMsg:    "ttl must be positive",
		},
		{
			name:        "capacity below one",
			modifier:    func(c *Config) { c.RateLimit.DefaultRule.Capacity = 0 },
			expectError: true,
			errorMsg:    "capacity must be at least 1",
		},
		{
			name:        "non-positive refill rate",
			modifier:    func(c *Config) { c.RateLimit.DefaultRule.RefillRate = 0 },
			expectError: true,
			errorMsg:    "refill_rate must be positive",
		},
		{
			name: "burst size disagreeing with capacity",
			modifier: func(c *Config) {
				c.RateLimit.DefaultRule.Capacity = 10
				c.RateLimit.DefaultRule.BurstSize = 3
			},
			expectError: true,
			errorMsg:    "burst_size is deprecated",
		},
		{
			name: "bypass enabled without header",
			modifier: func(c *Config) {
				c.RateLimit.Bypass.Enabled = true
				c.RateLimit.Bypass.Header = ""
			},
			expectError: true,
			errorMsg:    "bypass header is required",
		},
		{
			name: "invalid log level",
			modifier: func(c *Config) {
				c.Logging.Level = "loud"
			},
			expectError: true,
			errorMsg:    "invalid log level",
		},
		{
			// M5: PolicyFor (planes.go) returns the first rule whose
			// min_confidence a verdict clears, so the list must already be
			// sorted highest confidence first, as spec §5.1 documents it. A
			// list given in ascending order would make every high-confidence
			// verdict match the low-confidence rule first and never reach the
			// stricter one behind it, which under-enforces silently. Validate
			// rejects it instead of guessing which order was intended.
			name: "judgment policy rules out of order",
			modifier: func(c *Config) {
				c.Judgment.Policy["scraper"] = []PolicyRule{
					{MinConfidence: 0.6, Tier: "watch"},
					{MinConfidence: 0.8, Tier: "throttle"},
				}
			},
			expectError: true,
			errorMsg:    "must be in descending order",
		},
		{
			name: "judgment policy rules already descending",
			modifier: func(c *Config) {
				c.Judgment.Policy["scraper"] = []PolicyRule{
					{MinConfidence: 0.8, Tier: "throttle"},
					{MinConfidence: 0.6, Tier: "watch"},
				}
			},
		},
		{
			name: "invalid log format",
			modifier: func(c *Config) {
				c.Logging.Format = "xml"
			},
			expectError: true,
			errorMsg:    "invalid log format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.normalize()
			tt.modifier(cfg)

			err := cfg.Validate()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestLoad_FromFile(t *testing.T) {
	configPath := writeConfig(t, `
server:
  http_port: 8081
  grpc_port: 9091
  read_timeout: 15s
  read_header_timeout: 7s
  write_timeout: 15s
  idle_timeout: 45s
  shutdown_timeout: 45s
  max_header_bytes: 32768
  max_body_bytes: 4096
  trusted_proxies: ["10.0.0.0/8"]
  grpc_reflection: true

admin:
  tokens_env: MY_ADMIN_TOKENS

storage:
  backend: redis
  on_storage_error: allow

memory:
  cleanup_interval: 30s
  max_keys: 500

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
  ttl: 2h
  default_rule:
    name: "custom-default"
    capacity: 200
    refill_rate: 20
    period: 2m
  rules:
    api_heavy:
      capacity: 10
      refill_rate: 1
      period: 1m
  bypass:
    enabled: true
    header: "X-Bypass-Token"
    secrets_env: MY_BYPASS_SECRETS

metrics:
  enabled: true
  path: "/custom-metrics"

logging:
  level: "debug"
  format: "console"
  output: "stderr"
`)

	cfg, err := Load(configPath)
	require.NoError(t, err)

	assert.Equal(t, 8081, cfg.Server.HTTPPort)
	assert.Equal(t, 9091, cfg.Server.GRPCPort)
	assert.Equal(t, 15*time.Second, cfg.Server.ReadTimeout)
	assert.Equal(t, 7*time.Second, cfg.Server.ReadHeaderTimeout)
	assert.Equal(t, 45*time.Second, cfg.Server.IdleTimeout)
	assert.Equal(t, 32768, cfg.Server.MaxHeaderBytes)
	assert.Equal(t, int64(4096), cfg.Server.MaxBodyBytes)
	assert.Equal(t, []string{"10.0.0.0/8"}, cfg.Server.TrustedProxies)
	assert.True(t, cfg.Server.GRPCReflection)

	assert.Equal(t, "MY_ADMIN_TOKENS", cfg.Admin.TokensEnv)
	assert.Equal(t, BackendRedis, cfg.Storage.Backend)
	assert.Equal(t, OnStorageErrorAllow, cfg.Storage.OnStorageError)
	assert.Equal(t, 30*time.Second, cfg.Memory.CleanupInterval)
	assert.Equal(t, 500, cfg.Memory.MaxKeys)

	assert.Equal(t, "redis.example.com:6379", cfg.Redis.Address)
	assert.Equal(t, 1, cfg.Redis.DB)
	assert.Equal(t, 20, cfg.Redis.PoolSize)

	assert.Equal(t, "custom:", cfg.RateLimit.KeyPrefix)
	assert.Equal(t, 2*time.Hour, cfg.RateLimit.TTL)
	assert.Equal(t, "custom-default", cfg.RateLimit.DefaultRule.Name)
	assert.Equal(t, int64(200), cfg.RateLimit.DefaultRule.Capacity)
	assert.Equal(t, 2*time.Minute, cfg.RateLimit.DefaultRule.Period)
	assert.True(t, cfg.RateLimit.Bypass.Enabled)
	assert.Equal(t, "X-Bypass-Token", cfg.RateLimit.Bypass.Header)

	assert.Equal(t, "/custom-metrics", cfg.Metrics.Path)
	assert.Equal(t, "debug", cfg.Logging.Level)
	assert.Equal(t, "console", cfg.Logging.Format)
}

func TestLoad_FromEnv(t *testing.T) {
	configPath := writeConfig(t, "server:\n  http_port: 8080\n")

	t.Setenv("PORTCULLIS_SERVER_HTTP_PORT", "8888")
	t.Setenv("PORTCULLIS_REDIS_ADDRESS", "env-redis:6379")
	t.Setenv("PORTCULLIS_MEMORY_CLEANUP_INTERVAL", "5s")

	cfg, err := Load(configPath)
	require.NoError(t, err)

	assert.Equal(t, 8888, cfg.Server.HTTPPort)
	assert.Equal(t, "env-redis:6379", cfg.Redis.Address)
	assert.Equal(t, 5*time.Second, cfg.Memory.CleanupInterval)
	assert.Empty(t, cfg.Deprecations)
}

func TestLoad_LegacyEnvPrefixHonored(t *testing.T) {
	configPath := writeConfig(t, "server:\n  http_port: 8080\n")

	t.Setenv("RATE_LIMITER_SERVER_HTTP_PORT", "9999")

	cfg, err := Load(configPath)
	require.NoError(t, err)

	assert.Equal(t, 9999, cfg.Server.HTTPPort)
	assert.Contains(t, cfg.Deprecations, "RATE_LIMITER_SERVER_HTTP_PORT")
}

func TestLoad_CurrentEnvPrefixWins(t *testing.T) {
	configPath := writeConfig(t, "server:\n  http_port: 8080\n")

	t.Setenv("PORTCULLIS_SERVER_HTTP_PORT", "7777")
	t.Setenv("RATE_LIMITER_SERVER_HTTP_PORT", "9999")

	cfg, err := Load(configPath)
	require.NoError(t, err)

	assert.Equal(t, 7777, cfg.Server.HTTPPort)
	assert.Empty(t, cfg.Deprecations)
}

// TestConfig_BurstSizeDeprecated covers B8: burst_size is retired, accepted
// only when it agrees with capacity, and always reported.
func TestConfig_BurstSizeDeprecated(t *testing.T) {
	t.Run("agreeing value is accepted and reported", func(t *testing.T) {
		configPath := writeConfig(t, `
ratelimit:
  default_rule:
    name: default
    capacity: 25
    refill_rate: 25
    period: 1m
    burst_size: 25
`)
		cfg, err := Load(configPath)
		require.NoError(t, err)
		assert.Contains(t, cfg.Deprecations, "ratelimit.default_rule.burst_size")
		assert.Equal(t, int64(25), cfg.RateLimit.DefaultRule.Capacity)
	})

	t.Run("disagreeing value fails validation", func(t *testing.T) {
		configPath := writeConfig(t, `
ratelimit:
  default_rule:
    name: default
    capacity: 25
    refill_rate: 25
    period: 1m
    burst_size: 5
`)
		_, err := Load(configPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "burst_size is deprecated")
	})
}

// TestConfig_StorageBackend covers B17.
func TestConfig_StorageBackend(t *testing.T) {
	t.Run("defaults to memory", func(t *testing.T) {
		cfg, err := Load(writeConfig(t, "logging:\n  level: info\n"))
		require.NoError(t, err)
		assert.Equal(t, BackendMemory, cfg.Storage.Backend)
	})

	t.Run("from file", func(t *testing.T) {
		cfg, err := Load(writeConfig(t, "storage:\n  backend: redis\n"))
		require.NoError(t, err)
		assert.Equal(t, BackendRedis, cfg.Storage.Backend)
	})

	t.Run("from env", func(t *testing.T) {
		t.Setenv("PORTCULLIS_STORAGE_BACKEND", "redis")
		cfg, err := Load(writeConfig(t, "logging:\n  level: info\n"))
		require.NoError(t, err)
		assert.Equal(t, BackendRedis, cfg.Storage.Backend)
	})

	t.Run("rejects unknown backends", func(t *testing.T) {
		_, err := Load(writeConfig(t, "storage:\n  backend: tape\n"))
		require.Error(t, err)
	})
}

// TestConfig_MemoryCleanupInterval covers B18.
func TestConfig_MemoryCleanupInterval(t *testing.T) {
	t.Run("defaults to a minute", func(t *testing.T) {
		cfg, err := Load(writeConfig(t, "logging:\n  level: info\n"))
		require.NoError(t, err)
		assert.Equal(t, time.Minute, cfg.Memory.CleanupInterval)
	})

	t.Run("overridable", func(t *testing.T) {
		cfg, err := Load(writeConfig(t, "memory:\n  cleanup_interval: 15s\n"))
		require.NoError(t, err)
		assert.Equal(t, 15*time.Second, cfg.Memory.CleanupInterval)
	})
}

// TestConfig_CustomRuleCaseInsensitive covers B22: viper lowercases map keys,
// so lookups must lowercase too.
func TestConfig_CustomRuleCaseInsensitive(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
ratelimit:
  rules:
    Login:
      capacity: 7
      refill_rate: 7
      period: 1m
`))
	require.NoError(t, err)

	rule := cfg.GetCustomRule("Login")
	require.NotNil(t, rule)
	assert.Equal(t, int64(7), rule.Capacity)

	assert.NotNil(t, cfg.GetCustomRule("login"))
	assert.NotNil(t, cfg.GetCustomRule("LOGIN"))
	assert.Nil(t, cfg.GetCustomRule("missing"))
	assert.Nil(t, cfg.GetCustomRule(""))
}

func TestConfig_LegacyRuleShapeHonored(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
ratelimit:
  default_rules:
    - name: legacy-default
      capacity: 42
      refill_rate: 42
      period: 1m
  custom_rules:
    legacy:
      capacity: 3
      refill_rate: 3
      period: 1m
`))
	require.NoError(t, err)

	assert.Equal(t, "legacy-default", cfg.RateLimit.DefaultRule.Name)
	assert.Equal(t, int64(42), cfg.RateLimit.DefaultRule.Capacity)
	assert.NotNil(t, cfg.GetCustomRule("legacy"))
	assert.Contains(t, cfg.Deprecations, "ratelimit.default_rules")
	assert.Contains(t, cfg.Deprecations, "ratelimit.custom_rules")
}

func TestLoad_InvalidFile(t *testing.T) {
	configPath := writeConfig(t, "server:\n  http_port: \"not a number\"\n")

	_, err := Load(configPath)
	assert.Error(t, err)
}

func TestLoad_NonExistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(originalDir) }()
	_ = os.Chdir(tmpDir)

	cfg, err := Load("")
	require.NoError(t, err)
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
	t.Run("configured rule", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.normalize()
		rule := cfg.GetDefaultRule()
		assert.Equal(t, "default", rule.Name)
		assert.Equal(t, int64(100), rule.Capacity)
	})

	t.Run("zero value falls back to the built-in default", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.RateLimit.DefaultRule = ratelimiter.Rule{}
		rule := cfg.GetDefaultRule()
		assert.Equal(t, int64(100), rule.Capacity)
	})
}

func TestConfig_ToRateLimiterConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
ratelimit:
  key_prefix: "x:"
  ttl: 15m
  default_rule:
    name: default
    capacity: 20
    refill_rate: 20
    period: 1m
  rules:
    API_Heavy:
      capacity: 5
      refill_rate: 5
      period: 1m
`))
	require.NoError(t, err)

	rl := cfg.ToRateLimiterConfig()
	assert.Equal(t, "x:", rl.KeyPrefix)
	assert.Equal(t, 15*time.Minute, rl.TTL)
	assert.Equal(t, int64(20), rl.DefaultRule.Capacity)
	require.Contains(t, rl.Rules, "api_heavy")
	assert.Equal(t, int64(5), rl.Rules["api_heavy"].Capacity)
}

func TestBypassSecrets(t *testing.T) {
	t.Setenv("TEST_BYPASS_SECRETS", "one, two ,,three")
	cfg := BypassConfig{SecretsEnv: "TEST_BYPASS_SECRETS"}
	assert.Equal(t, []string{"one", "two", "three"}, cfg.Secrets())

	t.Setenv("TEST_BYPASS_EMPTY", "")
	assert.Nil(t, BypassConfig{SecretsEnv: "TEST_BYPASS_EMPTY"}.Secrets())
}

func TestAdminTokens(t *testing.T) {
	t.Setenv("TEST_ADMIN_TOKENS", "alpha,beta")
	assert.Equal(t, []string{"alpha", "beta"}, AdminConfig{TokensEnv: "TEST_ADMIN_TOKENS"}.Tokens())
}

// writeConfig writes a temporary config file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}
