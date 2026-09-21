package detect

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/signals"
)

// windowWithPaths returns a window whose only sampled path is path.
func windowWithPaths(path string) signals.IdentityWindow {
	window := testWindow("203.0.113.7", 10, longSpan)
	window.SampledPaths = []string{path}
	return window
}

// TestHardEvidence_ScannerPaths pins the built-in sensitive-path list, the
// case-insensitive matching, and the override.
func TestHardEvidence_ScannerPaths(t *testing.T) {
	opts := Options{}.WithDefaults().HardEvidence

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"environment file", "/.env", true},
		{"environment file in a subdirectory", "/app/.env.local", true},
		{"case insensitive", "/.ENV", true},
		{"git directory", "/.git/config", true},
		{"wordpress login", "/wp-login.php", true},
		{"wordpress admin", "/blog/wp-admin/", true},
		{"phpmyadmin", "/phpmyadmin/index.php", true},
		{"server status", "/server-status", true},
		{"actuator", "/actuator/health", true},
		{"aws credentials", "/.aws/credentials", true},
		{"config file", "/config.json", true},
		{"phpunit vendor", "/vendor/phpunit/phpunit", true},
		{"cgi-bin", "/cgi-bin/test.cgi", true},
		{"ordinary API path", "/api/orders", false},
		{"marker inside a word", "/myconfig.json", false},
		{"empty path", "", false},
		{"root", "/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			window := windowWithPaths(tt.path)
			flags := evidenceFlags(&window, opts, false)
			assert.Equal(t, tt.want, slices.Contains(flags, EvidenceScannerPaths))
		})
	}

	t.Run("a custom list replaces the built-in one", func(t *testing.T) {
		custom := opts
		custom.ScannerPaths = []string{"/custom-probe"}

		customPath := windowWithPaths("/custom-probe/x")
		assert.True(t, slices.Contains(
			evidenceFlags(&customPath, custom, false), EvidenceScannerPaths))

		builtinPath := windowWithPaths("/.env")
		assert.False(t, slices.Contains(
			evidenceFlags(&builtinPath, custom, false), EvidenceScannerPaths))
	})

	t.Run("the built-in list is a copy", func(t *testing.T) {
		paths := ScannerPaths()
		require.NotEmpty(t, paths)

		paths[0] = "/mutated"
		assert.Equal(t, "/.env", ScannerPaths()[0], "callers must not be able to mutate the built-in list")
	})
}

// TestHardEvidence_RateCeiling pins the flood threshold.
func TestHardEvidence_RateCeiling(t *testing.T) {
	opts := Options{}.WithDefaults().HardEvidence

	tests := []struct {
		name  string
		total int64
		want  bool
	}{
		{"below the ceiling", 2999, false},
		{"at the ceiling", 3000, true},
		{"above the ceiling", 6000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Windows are a minute long, so the ceiling of 50 rps is 3000.
			window := testWindow("203.0.113.7", tt.total, longSpan)
			flags := evidenceFlags(&window, opts, false)
			assert.Equal(t, tt.want, slices.Contains(flags, EvidenceRateOverHardCeiling))
		})
	}
}

// TestHardEvidence_AuthFailRatio pins the credential-stuffing threshold and the
// attempt gate in front of it.
func TestHardEvidence_AuthFailRatio(t *testing.T) {
	opts := Options{}.WithDefaults().HardEvidence

	tests := []struct {
		name     string
		attempts int64
		failures int64
		want     bool
	}{
		{"below the attempt gate", 9, 9, false},
		{"at the attempt gate, all failing", 10, 10, true},
		{"at the ratio threshold", 10, 8, true},
		{"just under the ratio threshold", 100, 79, false},
		{"no failures", 100, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			window := testWindow("203.0.113.7", 100, longSpan)
			window.AuthAttempts = tt.attempts
			window.AuthFailures = tt.failures

			flags := evidenceFlags(&window, opts, false)
			assert.Equal(t, tt.want, slices.Contains(flags, EvidenceAuthFailRatioHigh))
		})
	}
}

// TestHardEvidence_PrefixCampaign pins the campaign rule: four addresses in one
// aggregate prefix are a coincidence, five are a campaign.
func TestHardEvidence_PrefixCampaign(t *testing.T) {
	selector := NewDetector(Options{MaxSuspects: 64, MinScore: 1, MinRequests: 10})
	now := testNow()

	// flagsByldentity maps each suspect to whether it carries the campaign flag.
	flagsByIdentity := func(suspects []Suspect) map[string]bool {
		out := make(map[string]bool, len(suspects))
		for _, suspect := range suspects {
			out[suspect.Identity] = slices.Contains(suspect.Evidence, EvidencePrefixCampaign)
		}
		return out
	}

	assertCampaign := func(t *testing.T, windows []signals.IdentityWindow, want int, campaign bool) {
		t.Helper()

		suspects := selector.Select(windows, nil, now)
		require.Len(t, suspects, want)

		for identity, flagged := range flagsByIdentity(suspects) {
			assert.Equal(t, campaign, flagged, identity)
		}
	}

	t.Run("four IPv4 addresses in one /24", func(t *testing.T) {
		assertCampaign(t, suspiciousWindows("203.0.113.", 1, 4), 4, false)
	})
	t.Run("five IPv4 addresses in one /24", func(t *testing.T) {
		assertCampaign(t, suspiciousWindows("203.0.113.", 1, 5), 5, true)
	})
	t.Run("four IPv6 addresses in one /48", func(t *testing.T) {
		assertCampaign(t, suspiciousWindows("2001:db8:1::", 1, 4), 4, false)
	})
	t.Run("five IPv6 addresses in one /48", func(t *testing.T) {
		assertCampaign(t, suspiciousWindows("2001:db8:1::", 1, 5), 5, true)
	})
	t.Run("five addresses in five prefixes", func(t *testing.T) {
		windows := []signals.IdentityWindow{
			suspiciousWindow("203.0.113.1"),
			suspiciousWindow("198.51.100.1"),
			suspiciousWindow("192.0.2.1"),
			suspiciousWindow("10.0.0.1"),
			suspiciousWindow("172.16.0.1"),
		}
		assertCampaign(t, windows, 5, false)
	})
	t.Run("API keys cannot join a campaign", func(t *testing.T) {
		assertCampaign(t, suspiciousWindows("api-key-", 1, 5), 5, false)
	})
	t.Run("a prefix window is never a suspect", func(t *testing.T) {
		windows := append(suspiciousWindows("203.0.113.", 1, 4),
			suspiciousWindow("203.0.113.0/24"))

		suspects := selector.Select(windows, nil, now)
		require.Len(t, suspects, 4)
		for _, suspect := range suspects {
			assert.NotEqual(t, "203.0.113.0/24", suspect.Identity,
				"a prefix window is a rollup of its members, not a client")
			assert.NotContains(t, suspect.Evidence, EvidencePrefixCampaign)
		}
	})
}
