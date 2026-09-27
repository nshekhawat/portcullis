package main

import (
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/config"
)

// TestBuildJudge_TypeSafeWithoutAPIKeyFailsStartup is the regression for M6:
// a deployment configured for the typesafe judge must fail to start when its
// API key is absent, not silently run the rules judge instead. The policy
// thresholds in judgment.policy are tuned against the pinned model (spec §9),
// so quietly substituting the offline judge changes what the deployment
// actually enforces while looking healthy.
func TestBuildJudge_TypeSafeWithoutAPIKeyFailsStartup(t *testing.T) {
	t.Setenv("PORTCULLIS_TEST_MISSING_KEY", "")
	require.NoError(t, os.Unsetenv("PORTCULLIS_TEST_MISSING_KEY"))

	cfg := config.DefaultConfig()
	cfg.Judgment.Judge = config.JudgeTypeSafe
	cfg.Judgment.TypeSafe.APIKeyEnv = "PORTCULLIS_TEST_MISSING_KEY"

	_, err := buildJudge(cfg, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PORTCULLIS_TEST_MISSING_KEY")
}

// TestBuildJudge_TypeSafeWithAPIKeySucceeds is the non-regression case.
func TestBuildJudge_TypeSafeWithAPIKeySucceeds(t *testing.T) {
	t.Setenv("PORTCULLIS_TEST_PRESENT_KEY", "secret")

	cfg := config.DefaultConfig()
	cfg.Judgment.Judge = config.JudgeTypeSafe
	cfg.Judgment.TypeSafe.APIKeyEnv = "PORTCULLIS_TEST_PRESENT_KEY"

	j, err := buildJudge(cfg, zap.NewNop())
	require.NoError(t, err)
	assert.Equal(t, "typesafe", j.Name())
}

// TestBuildFallbackJudge_TypeSafeWithoutAPIKeyFailsStartup mirrors the primary
// judge's behavior: a fallback that cannot be constructed must fail startup
// rather than silently becoming "no fallback", which the controller would
// otherwise read as "no judge available" and skip cycles once the breaker
// opens.
func TestBuildFallbackJudge_TypeSafeWithoutAPIKeyFailsStartup(t *testing.T) {
	require.NoError(t, os.Unsetenv("PORTCULLIS_TEST_MISSING_FALLBACK_KEY"))

	cfg := config.DefaultConfig()
	cfg.Judgment.FallbackJudge = config.JudgeTypeSafe
	cfg.Judgment.TypeSafe.APIKeyEnv = "PORTCULLIS_TEST_MISSING_FALLBACK_KEY"

	_, err := buildFallbackJudge(cfg, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PORTCULLIS_TEST_MISSING_FALLBACK_KEY")
}

// TestBuildFallbackJudge_EmptyIsNotAnError checks the non-regression case: no
// fallback configured at all remains a legitimate, silent no-op.
func TestBuildFallbackJudge_EmptyIsNotAnError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Judgment.FallbackJudge = ""

	j, err := buildFallbackJudge(cfg, zap.NewNop())
	require.NoError(t, err)
	assert.Nil(t, j)
}

// TestBuildJudge_OpenAIWithoutAuth checks that a local server needs no key: an
// empty api_key_env builds the judge.
func TestBuildJudge_OpenAIWithoutAuth(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Judgment.Judge = config.JudgeOpenAI
	cfg.Judgment.OpenAI.Model = "local-model"

	j, err := buildJudge(cfg, zap.NewNop())
	require.NoError(t, err)
	assert.Equal(t, "openai", j.Name())

	cfg.Judgment.FallbackJudge = config.JudgeOpenAI
	j, err = buildFallbackJudge(cfg, zap.NewNop())
	require.NoError(t, err)
	assert.Equal(t, "openai", j.Name())
}

// TestBuildJudge_OpenAINamedKeyMissingFailsStartup: once an operator names a
// key variable, an unset variable is an error rather than a silent no-auth.
func TestBuildJudge_OpenAINamedKeyMissingFailsStartup(t *testing.T) {
	require.NoError(t, os.Unsetenv("PORTCULLIS_TEST_MISSING_OPENAI_KEY"))

	cfg := config.DefaultConfig()
	cfg.Judgment.Judge = config.JudgeOpenAI
	cfg.Judgment.OpenAI.Model = "local-model"
	cfg.Judgment.OpenAI.APIKeyEnv = "PORTCULLIS_TEST_MISSING_OPENAI_KEY"

	_, err := buildJudge(cfg, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PORTCULLIS_TEST_MISSING_OPENAI_KEY")
}

// TestBuildJudge_SystemOne checks the provider-agnostic System One judge:
// no auth by default, and a named but unset key fails startup.
func TestBuildJudge_SystemOne(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Judgment.Judge = config.JudgeSystemOne

	j, err := buildJudge(cfg, zap.NewNop())
	require.NoError(t, err)
	assert.Equal(t, "systemone", j.Name())

	cfg.Judgment.FallbackJudge = config.JudgeSystemOne
	j, err = buildFallbackJudge(cfg, zap.NewNop())
	require.NoError(t, err)
	assert.Equal(t, "systemone", j.Name())

	require.NoError(t, os.Unsetenv("PORTCULLIS_TEST_MISSING_SYSTEMONE_KEY"))
	cfg.Judgment.SystemOne.APIKeyEnv = "PORTCULLIS_TEST_MISSING_SYSTEMONE_KEY"
	_, err = buildJudge(cfg, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PORTCULLIS_TEST_MISSING_SYSTEMONE_KEY")
}

// TestBuildGuardrails_MalformedCIDRFailsStartup is the regression for L4: a
// guardrails.allowlist entry that looks like a CIDR but does not parse (a
// typo, such as a /33 or an out-of-range octet) used to be silently
// reinterpreted as an exact-identity match — a string that can never equal a
// real identity, so the entry became a permanent no-op with no error at
// startup. Since the allowlist is the "never escalated" list, a silent no-op
// there is worth failing loudly for.
func TestBuildGuardrails_MalformedCIDRFailsStartup(t *testing.T) {
	cfg := config.DefaultConfig().Judgment
	cfg.Guardrails.Allowlist = []string{"10.0.0.0/33"}

	_, err := buildGuardrails(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "10.0.0.0/33")
}

// TestBuildGuardrails_ValidEntries is the non-regression case: real CIDRs,
// bare addresses, and non-address identities (API keys, service names) all
// still work.
func TestBuildGuardrails_ValidEntries(t *testing.T) {
	cfg := config.DefaultConfig().Judgment
	cfg.Guardrails.Allowlist = []string{"10.0.0.0/8", "127.0.0.1", "service-account"}

	g, err := buildGuardrails(cfg)
	require.NoError(t, err)
	assert.Len(t, g.Allowlist, 2, "the CIDR and the bare address both become prefixes")
	assert.Contains(t, g.Allowlist, netip.MustParsePrefix("10.0.0.0/8"))
	assert.True(t, g.AllowlistIdentities["service-account"])
}
