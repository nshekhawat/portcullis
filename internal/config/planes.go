package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/policy"
)

// Judgment modes.
const (
	ModeOff     = "off"
	ModeShadow  = "shadow"
	ModeEnforce = "enforce"
)

// Judge implementations.
const (
	JudgeRules    = "rules"
	JudgeTypeSafe = "typesafe"
	JudgeMock     = "mock"
)

// SignalsConfig configures the observation pipeline.
type SignalsConfig struct {
	Enabled                 bool          `mapstructure:"enabled"`
	Buffer                  int           `mapstructure:"buffer"`
	Window                  time.Duration `mapstructure:"window"`
	MaxIdentities           int           `mapstructure:"max_identities"`
	SampledPathsPerIdentity int           `mapstructure:"sampled_paths_per_identity"`
	AggregatePrefixes       bool          `mapstructure:"aggregate_prefixes"`
}

// DetectionConfig configures the detection plane.
type DetectionConfig struct {
	Interval     time.Duration      `mapstructure:"interval"`
	MaxSuspects  int                `mapstructure:"max_suspects"`
	MinScore     float64            `mapstructure:"min_score"`
	MinRequests  int                `mapstructure:"min_requests"`
	HardEvidence HardEvidenceConfig `mapstructure:"hard_evidence"`
}

// HardEvidenceConfig configures the deterministic evidence rules.
type HardEvidenceConfig struct {
	RPSCeiling       float64 `mapstructure:"rps_ceiling"`
	AuthFailRatio    float64 `mapstructure:"auth_fail_ratio"`
	ScannerPathsFile string  `mapstructure:"scanner_paths_file"`
}

// JudgmentConfig configures the judgment plane.
type JudgmentConfig struct {
	Mode           string                       `mapstructure:"mode"`
	Judge          string                       `mapstructure:"judge"`
	FallbackJudge  string                       `mapstructure:"fallback_judge"`
	Timeout        time.Duration                `mapstructure:"timeout"`
	Budget         BudgetConfig                 `mapstructure:"budget"`
	CircuitBreaker CircuitBreakerConfig         `mapstructure:"circuit_breaker"`
	TypeSafe       TypeSafeConfig               `mapstructure:"typesafe"`
	Policy         map[string][]PolicyRule      `mapstructure:"policy"`
	MinConfidence  float64                      `mapstructure:"min_confidence_to_act"`
	Tiers          map[string]policy.TierConfig `mapstructure:"tiers"`
	Guardrails     GuardrailsConfig             `mapstructure:"guardrails"`
	Audit          AuditConfig                  `mapstructure:"audit"`
}

// BudgetConfig bounds judge usage.
type BudgetConfig struct {
	MaxCallsPerMinute    int   `mapstructure:"max_calls_per_minute"`
	MaxInputTokensPerDay int64 `mapstructure:"max_input_tokens_per_day"`
}

// CircuitBreakerConfig configures the in-house breaker.
type CircuitBreakerConfig struct {
	Failures int           `mapstructure:"failures"`
	OpenFor  time.Duration `mapstructure:"open_for"`
}

// TypeSafeConfig configures the TypeSafe System One judge.
type TypeSafeConfig struct {
	BaseURL          string `mapstructure:"base_url"`
	APIKeyEnv        string `mapstructure:"api_key_env"`
	Model            string `mapstructure:"model"`
	SendSampledPaths bool   `mapstructure:"send_sampled_paths"`
}

// PolicyRule maps a label and confidence floor onto a tier.
type PolicyRule struct {
	MinConfidence float64 `mapstructure:"min_confidence"`
	Tier          string  `mapstructure:"tier"`
}

// GuardrailsConfig holds the code-level limits the model cannot override.
type GuardrailsConfig struct {
	Allowlist                 []string      `mapstructure:"allowlist"`
	BlockMinConfidence        float64       `mapstructure:"block_min_confidence"`
	BlockRequiresHardEvidence bool          `mapstructure:"block_requires_hard_evidence"`
	MaxNewBlocksPerCycle      int           `mapstructure:"max_new_blocks_per_cycle"`
	MaxNonNormalFraction      float64       `mapstructure:"max_non_normal_fraction"`
	MaxTTL                    time.Duration `mapstructure:"max_ttl"`
}

// AuditConfig configures the decision audit trail.
type AuditConfig struct {
	RingSize int  `mapstructure:"ring_size"`
	Log      bool `mapstructure:"log"`
}

// DefaultSignalsConfig returns the default observation settings.
func DefaultSignalsConfig() SignalsConfig {
	return SignalsConfig{
		Enabled:                 true,
		Buffer:                  65536,
		Window:                  60 * time.Second,
		MaxIdentities:           200_000,
		SampledPathsPerIdentity: 8,
		AggregatePrefixes:       true,
	}
}

// DefaultDetectionConfig returns the default detection settings.
func DefaultDetectionConfig() DetectionConfig {
	return DetectionConfig{
		Interval:    10 * time.Second,
		MaxSuspects: 25,
		MinScore:    3.0,
		MinRequests: 20,
		HardEvidence: HardEvidenceConfig{
			RPSCeiling:    50,
			AuthFailRatio: 0.8,
		},
	}
}

// DefaultJudgmentConfig returns the default judgment settings.
func DefaultJudgmentConfig() JudgmentConfig {
	return JudgmentConfig{
		Mode:          ModeShadow,
		Judge:         JudgeRules,
		FallbackJudge: JudgeRules,
		Timeout:       2 * time.Second,
		Budget: BudgetConfig{
			MaxCallsPerMinute:    12,
			MaxInputTokensPerDay: 20_000_000,
		},
		CircuitBreaker: CircuitBreakerConfig{Failures: 3, OpenFor: 30 * time.Second},
		//nolint:gosec // APIKeyEnv names the environment variable, it holds no secret
		TypeSafe: TypeSafeConfig{
			BaseURL:          "https://api.typesafe.ai",
			APIKeyEnv:        "TYPESAFE_API_KEY",
			Model:            "jev-1.13.0",
			SendSampledPaths: true,
		},
		Policy:        defaultPolicy(),
		MinConfidence: 0.6,
		Tiers: map[string]policy.TierConfig{
			"watch":    {Multiplier: 1.0, TTL: 10 * time.Minute},
			"throttle": {Multiplier: 0.25, TTL: 15 * time.Minute},
			"strict":   {Multiplier: 0.05, TTL: 30 * time.Minute},
			"block":    {Multiplier: 0.0, TTL: 60 * time.Minute, Status: 429},
		},
		Guardrails: GuardrailsConfig{
			Allowlist:                 []string{"127.0.0.1/32"},
			BlockMinConfidence:        0.9,
			BlockRequiresHardEvidence: true,
			MaxNewBlocksPerCycle:      5,
			MaxNonNormalFraction:      0.02,
			MaxTTL:                    24 * time.Hour,
		},
		Audit: AuditConfig{RingSize: 2000, Log: true},
	}
}

// defaultPolicy returns the shipped label-to-tier matrix.
func defaultPolicy() map[string][]PolicyRule {
	return map[string][]PolicyRule{
		string(judge.LabelLegitimateBurst):   {{MinConfidence: 0.0, Tier: "normal"}},
		string(judge.LabelBenignCrawler):     {{MinConfidence: 0.0, Tier: "normal"}},
		string(judge.LabelMisbehavingClient): {{MinConfidence: 0.75, Tier: "throttle"}, {MinConfidence: 0.0, Tier: "watch"}},
		string(judge.LabelScraper):           {{MinConfidence: 0.8, Tier: "throttle"}, {MinConfidence: 0.6, Tier: "watch"}},
		//nolint:gosec // label names, not secrets
		string(judge.LabelCredentialStuffing):   {{MinConfidence: 0.85, Tier: "strict"}, {MinConfidence: 0.6, Tier: "throttle"}},
		string(judge.LabelVulnerabilityScanner): {{MinConfidence: 0.85, Tier: "block"}, {MinConfidence: 0.6, Tier: "strict"}},
		string(judge.LabelAPIEnumeration):       {{MinConfidence: 0.8, Tier: "strict"}, {MinConfidence: 0.6, Tier: "throttle"}},
		string(judge.LabelL7Flood):              {{MinConfidence: 0.8, Tier: "block"}, {MinConfidence: 0.6, Tier: "strict"}},
	}
}

// setPlaneDefaults registers the signals, detection and judgment defaults.
func setPlaneDefaults(v *viper.Viper) {
	signals := DefaultSignalsConfig()
	v.SetDefault("signals.enabled", signals.Enabled)
	v.SetDefault("signals.buffer", signals.Buffer)
	v.SetDefault("signals.window", signals.Window.String())
	v.SetDefault("signals.max_identities", signals.MaxIdentities)
	v.SetDefault("signals.sampled_paths_per_identity", signals.SampledPathsPerIdentity)
	v.SetDefault("signals.aggregate_prefixes", signals.AggregatePrefixes)

	detection := DefaultDetectionConfig()
	v.SetDefault("detection.interval", detection.Interval.String())
	v.SetDefault("detection.max_suspects", detection.MaxSuspects)
	v.SetDefault("detection.min_score", detection.MinScore)
	v.SetDefault("detection.min_requests", detection.MinRequests)
	v.SetDefault("detection.hard_evidence.rps_ceiling", detection.HardEvidence.RPSCeiling)
	v.SetDefault("detection.hard_evidence.auth_fail_ratio", detection.HardEvidence.AuthFailRatio)

	judgment := DefaultJudgmentConfig()
	v.SetDefault("judgment.mode", judgment.Mode)
	v.SetDefault("judgment.judge", judgment.Judge)
	v.SetDefault("judgment.fallback_judge", judgment.FallbackJudge)
	v.SetDefault("judgment.timeout", judgment.Timeout.String())
	v.SetDefault("judgment.budget.max_calls_per_minute", judgment.Budget.MaxCallsPerMinute)
	v.SetDefault("judgment.budget.max_input_tokens_per_day", judgment.Budget.MaxInputTokensPerDay)
	v.SetDefault("judgment.circuit_breaker.failures", judgment.CircuitBreaker.Failures)
	v.SetDefault("judgment.circuit_breaker.open_for", judgment.CircuitBreaker.OpenFor.String())
	v.SetDefault("judgment.typesafe.base_url", judgment.TypeSafe.BaseURL)
	v.SetDefault("judgment.typesafe.api_key_env", judgment.TypeSafe.APIKeyEnv)
	v.SetDefault("judgment.typesafe.model", judgment.TypeSafe.Model)
	v.SetDefault("judgment.typesafe.send_sampled_paths", judgment.TypeSafe.SendSampledPaths)
	v.SetDefault("judgment.min_confidence_to_act", judgment.MinConfidence)
	v.SetDefault("judgment.guardrails.allowlist", judgment.Guardrails.Allowlist)
	v.SetDefault("judgment.guardrails.block_min_confidence", judgment.Guardrails.BlockMinConfidence)
	v.SetDefault("judgment.guardrails.block_requires_hard_evidence", judgment.Guardrails.BlockRequiresHardEvidence)
	v.SetDefault("judgment.guardrails.max_new_blocks_per_cycle", judgment.Guardrails.MaxNewBlocksPerCycle)
	v.SetDefault("judgment.guardrails.max_non_normal_fraction", judgment.Guardrails.MaxNonNormalFraction)
	v.SetDefault("judgment.guardrails.max_ttl", judgment.Guardrails.MaxTTL.String())
	v.SetDefault("judgment.audit.ring_size", judgment.Audit.RingSize)
	v.SetDefault("judgment.audit.log", judgment.Audit.Log)
}

// normalizePlanes fills in plane defaults that viper may have left zero-valued
// when the caller supplied a partial map (notably for tiers and policy).
func (c *Config) normalizePlanes() {
	def := DefaultJudgmentConfig()

	if c.Signals.Buffer == 0 {
		c.Signals = DefaultSignalsConfig()
	}
	if c.Detection.MaxSuspects == 0 {
		c.Detection = DefaultDetectionConfig()
	}
	if c.Judgment.Tiers == nil {
		c.Judgment.Tiers = def.Tiers
	}
	if c.Judgment.Policy == nil {
		c.Judgment.Policy = def.Policy
	}
	if c.Judgment.Guardrails.MaxTTL == 0 {
		c.Judgment.Guardrails.MaxTTL = def.Guardrails.MaxTTL
	}
	if c.Judgment.Audit.RingSize == 0 {
		c.Judgment.Audit = def.Audit
	}
	if c.Judgment.Timeout == 0 {
		c.Judgment.Timeout = def.Timeout
	}
	if c.Judgment.Budget.MaxCallsPerMinute == 0 {
		c.Judgment.Budget = def.Budget
	}
	if c.Judgment.CircuitBreaker.Failures == 0 {
		c.Judgment.CircuitBreaker = def.CircuitBreaker
	}
	if c.Judgment.TypeSafe.BaseURL == "" {
		c.Judgment.TypeSafe = def.TypeSafe
	}
}

// TierConfigs converts the configured tiers into policy tier configs.
func (j *JudgmentConfig) TierConfigs() (map[policy.Tier]policy.TierConfig, error) {
	out := make(map[policy.Tier]policy.TierConfig, len(j.Tiers))
	for name, cfg := range j.Tiers {
		tier, err := policy.ParseTier(name)
		if err != nil {
			return nil, err
		}
		out[tier] = cfg
	}
	return out, nil
}

// PolicyFor returns the tier proposed for a label at a confidence, or
// policy.TierNormal when the label is unknown or the confidence is below every
// configured floor.
func (j *JudgmentConfig) PolicyFor(label judge.Label, confidence float64) (policy.Tier, bool) {
	rules, ok := j.Policy[strings.ToLower(string(label))]
	if !ok {
		return policy.TierNormal, false
	}
	for _, rule := range rules {
		if confidence >= rule.MinConfidence {
			tier, err := policy.ParseTier(rule.Tier)
			if err != nil {
				return policy.TierNormal, false
			}
			return tier, true
		}
	}
	return policy.TierNormal, false
}

// validatePlanes validates the signals, detection and judgment sections.
func (c *Config) validatePlanes() error {
	if c.Signals.Buffer < 1 {
		return fmt.Errorf("signals buffer must be at least 1")
	}
	if c.Signals.Window <= 0 {
		return fmt.Errorf("signals window must be positive")
	}
	if c.Signals.MaxIdentities < 1 {
		return fmt.Errorf("signals max_identities must be at least 1")
	}
	if c.Signals.SampledPathsPerIdentity < 1 {
		return fmt.Errorf("signals sampled_paths_per_identity must be at least 1")
	}

	if c.Detection.Interval <= 0 {
		return fmt.Errorf("detection interval must be positive")
	}
	if c.Detection.MaxSuspects < 1 {
		return fmt.Errorf("detection max_suspects must be at least 1")
	}
	if c.Detection.MinScore < 0 {
		return fmt.Errorf("detection min_score must not be negative")
	}
	if c.Detection.MinRequests < 0 {
		return fmt.Errorf("detection min_requests must not be negative")
	}
	if c.Detection.HardEvidence.RPSCeiling <= 0 {
		return fmt.Errorf("detection hard_evidence.rps_ceiling must be positive")
	}
	if r := c.Detection.HardEvidence.AuthFailRatio; r <= 0 || r > 1 {
		return fmt.Errorf("detection hard_evidence.auth_fail_ratio must be in (0, 1]")
	}

	switch c.Judgment.Mode {
	case ModeOff, ModeShadow, ModeEnforce:
	default:
		return fmt.Errorf("invalid judgment mode %q (want %q, %q or %q)",
			c.Judgment.Mode, ModeOff, ModeShadow, ModeEnforce)
	}
	if err := validateJudgeName("judgment.judge", c.Judgment.Judge, false); err != nil {
		return err
	}
	if err := validateJudgeName("judgment.fallback_judge", c.Judgment.FallbackJudge, true); err != nil {
		return err
	}
	if c.Judgment.Timeout <= 0 {
		return fmt.Errorf("judgment timeout must be positive")
	}
	if c.Judgment.Budget.MaxCallsPerMinute < 1 {
		return fmt.Errorf("judgment budget.max_calls_per_minute must be at least 1")
	}
	if c.Judgment.Budget.MaxInputTokensPerDay < 0 {
		return fmt.Errorf("judgment budget.max_input_tokens_per_day must not be negative")
	}
	if c.Judgment.CircuitBreaker.Failures < 1 {
		return fmt.Errorf("judgment circuit_breaker.failures must be at least 1")
	}
	if c.Judgment.CircuitBreaker.OpenFor <= 0 {
		return fmt.Errorf("judgment circuit_breaker.open_for must be positive")
	}
	if c.Judgment.TypeSafe.BaseURL == "" {
		return fmt.Errorf("judgment typesafe.base_url is required")
	}
	if c.Judgment.TypeSafe.Model == "" {
		return fmt.Errorf("judgment typesafe.model is required")
	}
	if r := c.Judgment.MinConfidence; r < 0 || r > 1 {
		return fmt.Errorf("judgment min_confidence_to_act must be in [0, 1]")
	}

	if len(c.Judgment.Tiers) == 0 {
		return fmt.Errorf("judgment tiers must not be empty")
	}
	for name, tier := range c.Judgment.Tiers {
		if _, err := policy.ParseTier(name); err != nil {
			return fmt.Errorf("judgment tiers: %w", err)
		}
		if tier.Multiplier < 0 || tier.Multiplier > 1 {
			return fmt.Errorf("judgment tiers.%s multiplier must be in [0, 1]", name)
		}
		if tier.TTL <= 0 {
			return fmt.Errorf("judgment tiers.%s ttl must be positive", name)
		}
	}

	for label, rules := range c.Judgment.Policy {
		if _, err := judge.ParseLabel(label); err != nil {
			return fmt.Errorf("judgment policy: %w", err)
		}
		if len(rules) == 0 {
			return fmt.Errorf("judgment policy.%s must have at least one rule", label)
		}
		for i, rule := range rules {
			if rule.MinConfidence < 0 || rule.MinConfidence > 1 {
				return fmt.Errorf("judgment policy.%s[%d] min_confidence must be in [0, 1]", label, i)
			}
			if _, err := policy.ParseTier(rule.Tier); err != nil {
				return fmt.Errorf("judgment policy.%s[%d]: %w", label, i, err)
			}
		}
	}

	g := c.Judgment.Guardrails
	if g.BlockMinConfidence < 0 || g.BlockMinConfidence > 1 {
		return fmt.Errorf("judgment guardrails.block_min_confidence must be in [0, 1]")
	}
	if g.MaxNewBlocksPerCycle < 0 {
		return fmt.Errorf("judgment guardrails.max_new_blocks_per_cycle must not be negative")
	}
	if g.MaxNonNormalFraction < 0 || g.MaxNonNormalFraction > 1 {
		return fmt.Errorf("judgment guardrails.max_non_normal_fraction must be in [0, 1]")
	}
	if g.MaxTTL <= 0 {
		return fmt.Errorf("judgment guardrails.max_ttl must be positive")
	}

	if c.Judgment.Audit.RingSize < 1 {
		return fmt.Errorf("judgment audit.ring_size must be at least 1")
	}

	return nil
}

// validateJudgeName checks a configured judge name. allowEmpty permits the
// fallback being disabled.
func validateJudgeName(field, name string, allowEmpty bool) error {
	if name == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s is required", field)
	}
	switch name {
	case JudgeRules, JudgeTypeSafe, JudgeMock:
		return nil
	default:
		return fmt.Errorf("invalid %s %q (want %q, %q or %q)",
			field, name, JudgeRules, JudgeTypeSafe, JudgeMock)
	}
}
