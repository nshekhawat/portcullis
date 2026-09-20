package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// GatewayConfig configures gateway mode (spec §5.8).
type GatewayConfig struct {
	// Listen is the proxying listener.
	Listen string `mapstructure:"listen"`
	// AdminListen is the health and admin listener; it is never proxied.
	AdminListen string `mapstructure:"admin_listen"`
	// Upstream is the application being protected. The --upstream flag wins.
	Upstream string `mapstructure:"upstream"`
	// Routes maps path prefixes onto named rules.
	Routes []GatewayRoute `mapstructure:"routes"`
	// IdentifierHeader carries an explicit identity for the limiter.
	IdentifierHeader string `mapstructure:"identifier_header"`
	// APIKeyHeader carries an API key used as the identity when present.
	APIKeyHeader string `mapstructure:"api_key_header"`
	// MaxBodyBytes caps proxied request bodies. Zero means no cap.
	MaxBodyBytes int64 `mapstructure:"max_body_bytes"`
	// ShutdownTimeout bounds a graceful stop.
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
}

// GatewayRoute is one path-prefix rule.
type GatewayRoute struct {
	Prefix string `mapstructure:"prefix"`
	Rule   string `mapstructure:"rule"`
}

// DefaultGatewayConfig returns the gateway defaults.
//
//nolint:gosec // header names, not credentials
func DefaultGatewayConfig() GatewayConfig {
	return GatewayConfig{
		Listen:           ":8000",
		AdminListen:      ":8081",
		IdentifierHeader: "X-Portcullis-Identity",
		APIKeyHeader:     "X-Portcullis-Key",
		MaxBodyBytes:     1 << 20,
		ShutdownTimeout:  30 * time.Second,
	}
}

// setGatewayDefaults registers the gateway defaults.
func setGatewayDefaults(v *viper.Viper) {
	gw := DefaultGatewayConfig()
	v.SetDefault("gateway.listen", gw.Listen)
	v.SetDefault("gateway.admin_listen", gw.AdminListen)
	v.SetDefault("gateway.identifier_header", gw.IdentifierHeader)
	v.SetDefault("gateway.api_key_header", gw.APIKeyHeader)
	v.SetDefault("gateway.max_body_bytes", gw.MaxBodyBytes)
	v.SetDefault("gateway.shutdown_timeout", gw.ShutdownTimeout.String())
}

// normalizeGateway fills in gateway defaults when a partial block was supplied.
func (c *Config) normalizeGateway() {
	def := DefaultGatewayConfig()
	if c.Gateway.Listen == "" {
		c.Gateway.Listen = def.Listen
	}
	if c.Gateway.AdminListen == "" {
		c.Gateway.AdminListen = def.AdminListen
	}
	if c.Gateway.IdentifierHeader == "" {
		c.Gateway.IdentifierHeader = def.IdentifierHeader
	}
	if c.Gateway.APIKeyHeader == "" {
		c.Gateway.APIKeyHeader = def.APIKeyHeader
	}
	if c.Gateway.MaxBodyBytes <= 0 {
		c.Gateway.MaxBodyBytes = def.MaxBodyBytes
	}
	if c.Gateway.ShutdownTimeout <= 0 {
		c.Gateway.ShutdownTimeout = def.ShutdownTimeout
	}
}

// validateGateway validates the gateway section.
func (c *Config) validateGateway() error {
	if c.Gateway.Listen == c.Gateway.AdminListen {
		return fmt.Errorf("gateway listen and admin_listen must differ")
	}
	if c.Gateway.ShutdownTimeout <= 0 {
		return fmt.Errorf("gateway shutdown_timeout must be positive")
	}

	for i, route := range c.Gateway.Routes {
		if !strings.HasPrefix(route.Prefix, "/") {
			return fmt.Errorf("gateway routes[%d].prefix must start with %q", i, "/")
		}
		if route.Rule == "" {
			return fmt.Errorf("gateway routes[%d].rule is required", i)
		}
		if _, ok := c.RateLimit.Rules[strings.ToLower(route.Rule)]; !ok {
			return fmt.Errorf("gateway routes[%d].rule %q is not defined in ratelimit.rules", i, route.Rule)
		}
	}

	return nil
}
