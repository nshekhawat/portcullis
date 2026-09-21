package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// adminClient talks to the admin API.
type adminClient struct {
	baseURL string
	token   string
	client  *http.Client
}

// defaultAdminURL is the gateway's admin listener; serve mode uses the service
// port instead (pass --url).
const defaultAdminURL = "http://127.0.0.1:8081"

// runAdmin implements the `portcullis admin` subcommand.
func runAdmin(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, adminUsage)
		return errors.New("no admin command given")
	}

	sub := args[0]
	flags := flag.NewFlagSet("admin "+sub, flag.ContinueOnError)
	baseURL := flags.String("url", defaultAdminURL, "admin API base URL")
	token := flags.String("token", defaultAdminToken(), "admin bearer token")
	watch := flags.Bool("watch", false, "keep printing the table until interrupted")
	interval := flags.Duration("interval", 2*time.Second, "refresh interval for --watch")
	limit := flags.Int("limit", 100, "maximum decisions to fetch")
	ttl := flags.Duration("ttl", 0, "tier lifetime, e.g. 15m (defaults to the tier's own TTL)")

	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	client := &adminClient{baseURL: strings.TrimRight(*baseURL, "/"), token: *token, client: &http.Client{Timeout: 5 * time.Second}}

	switch sub {
	case "tiers":
		return client.showTiers(*watch, *interval, *limit)
	case "decisions":
		return client.showDecisions(*limit)
	case "set-tier":
		if flags.NArg() < 2 {
			return errors.New("usage: portcullis admin set-tier <identity> <tier> [--ttl 15m]")
		}
		return client.setTier(flags.Arg(0), flags.Arg(1), *ttl)
	case "clear-tier":
		if flags.NArg() < 1 {
			return errors.New("usage: portcullis admin clear-tier <identity>")
		}
		return client.clearTier(flags.Arg(0))
	case "mode":
		if flags.NArg() == 0 {
			return client.showMode()
		}
		return client.setMode(flags.Arg(0))
	default:
		return fmt.Errorf("unknown admin command %q\n\n%s", sub, adminUsage)
	}
}

const adminUsage = `usage: portcullis admin <command> [flags] [args]

Flags must come before the trailing arguments (identity, tier, mode): the
standard library's flag package stops parsing flags at the first one, so
anything after it, including later --flags, is taken literally rather than
recognized.

Commands:
  tiers [--watch]                       list active tiers, joined with their decisions
  decisions [--limit N]                 list recent judgment decisions
  set-tier [--ttl] <identity> <tier>    set a manual tier
  clear-tier <identity>                 remove a tier
  mode [off|shadow|enforce]             show or change the judgment mode

Flags:
  --url      admin API base URL (default ` + defaultAdminURL + `)
  --token    admin bearer token (default $PORTCULLIS_ADMIN_TOKENS, first entry)

Examples:
  portcullis admin mode --url http://localhost:8001 --token $TOKEN enforce
  portcullis admin set-tier --url http://localhost:8001 --token $TOKEN --ttl 15m 203.0.113.7 throttle
`

// defaultAdminToken takes the first configured admin token.
func defaultAdminToken() string {
	raw := os.Getenv("PORTCULLIS_ADMIN_TOKENS")
	if raw == "" {
		return ""
	}
	if idx := strings.IndexByte(raw, ','); idx >= 0 {
		return strings.TrimSpace(raw[:idx])
	}
	return strings.TrimSpace(raw)
}

// tierView mirrors the admin API's tier representation.
type tierView struct {
	Identity   string `json:"identity"`
	Tier       string `json:"tier"`
	Until      string `json:"until"`
	Source     string `json:"source"`
	DecisionID string `json:"decision_id"`
}

// decisionView mirrors the admin API's decision representation.
type decisionView struct {
	ID         string    `json:"id"`
	Identity   string    `json:"identity"`
	Label      string    `json:"label"`
	Confidence float64   `json:"confidence"`
	Evidence   []string  `json:"evidence"`
	Judge      string    `json:"judge"`
	Applied    string    `json:"applied_tier"`
	At         time.Time `json:"at"`
}

// tierListResponse is the tiers endpoint's body.
type tierListResponse struct {
	Tiers []tierView `json:"tiers"`
}

// decisionListResponse is the decisions endpoint's body.
type decisionListResponse struct {
	Decisions []decisionView `json:"decisions"`
}

// modeResponse is the mode endpoint's body.
type modeResponse struct {
	Mode string `json:"mode"`
}

// showTiers prints the tier table, optionally refreshing until interrupted.
func (c *adminClient) showTiers(watch bool, interval time.Duration, limit int) error {
	for {
		tiers, err := c.fetchTiers()
		if err != nil {
			return err
		}

		// The tier's decision may be far back in a busy ring, so look the
		// identity up directly: the newest decision for it is the one that
		// produced the entry.
		decisions := make(map[string]decisionView, len(tiers))
		for _, tier := range tiers {
			if tier.Tier == "normal" {
				continue
			}
			if d, ok := c.fetchTierDecision(tier); ok {
				decisions[tier.Identity] = d
			}
		}

		mode, err := c.fetchMode()
		if err != nil {
			return err
		}
		stats := c.fetchJudgeStats()

		fmt.Print(renderTiers(tiers, decisions, mode, stats))
		if !watch {
			return nil
		}
		time.Sleep(interval)
	}
}

// judgeStats summarizes the judge's health for the table footer.
type judgeStats struct {
	judge       string
	meanLatency time.Duration
	hasLatency  bool
	breaker     string
}

// renderTiers formats the table the demo prints.
func renderTiers(tiers []tierView, decisions map[string]decisionView, mode string, stats judgeStats) string {
	sort.Slice(tiers, func(i, j int) bool {
		if tiers[i].Tier != tiers[j].Tier {
			return tiers[i].Tier > tiers[j].Tier
		}
		return tiers[i].Identity < tiers[j].Identity
	})

	var b strings.Builder
	fmt.Fprintf(&b, "%-24s %-9s %-22s %-5s %-24s %s\n", "IDENTITY", "TIER", "LABEL", "CONF", "EVIDENCE", "TTL")

	normal := 0
	//nolint:gocritic // tierView is small and this runs once per refresh
	for _, tier := range tiers {
		if tier.Tier == "normal" {
			normal++
			continue
		}

		label, conf, evidence := "-", "", "-"
		if d, ok := decisions[tier.Identity]; ok {
			label = d.Label
			conf = fmt.Sprintf("%.2f", d.Confidence)
			if len(d.Evidence) > 0 {
				evidence = strings.Join(d.Evidence, ",")
			}
		}

		fmt.Fprintf(&b, "%-24s %-9s %-22s %-5s %-24s %s\n",
			tier.Identity, tier.Tier, label, conf, evidence, formatTTL(tier.Until, time.Now()))
	}

	if normal > 0 {
		fmt.Fprintf(&b, "(%d identities normal)\n", normal)
	}

	summaries := make([]string, 0, 4)
	if stats.judge != "" {
		summaries = append(summaries, "judge="+stats.judge)
	}
	if stats.hasLatency {
		summaries = append(summaries, "mean_latency="+stats.meanLatency.String())
	}
	if stats.breaker != "" {
		summaries = append(summaries, "breaker="+stats.breaker)
	}
	summaries = append(summaries, fmt.Sprintf("shadow=%v", mode == "shadow"))
	fmt.Fprintf(&b, "(%d identities normal)   %s\n", normal, strings.Join(summaries, "   "))
	return b.String()
}

// fetchJudgeStats reads the judge's health from the metrics endpoint. It is
// best-effort: a failure simply leaves the footer fields empty.
func (c *adminClient) fetchJudgeStats() judgeStats {
	//nolint:gosec // the operator supplies the admin URL; fetching it is the point
	resp, err := c.client.Get(c.baseURL + "/metrics")
	if err != nil {
		return judgeStats{}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return judgeStats{}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return judgeStats{}
	}

	return parseJudgeStats(string(body))
}

// parseJudgeStats extracts the mean judge latency and the breaker state from a
// Prometheus exposition body. It reports the mean rather than a percentile so
// the number it prints is one it can actually justify.
func parseJudgeStats(body string) judgeStats {
	var (
		stats        judgeStats
		latencySum   float64
		latencyCount float64
		breakerMax   = -1.0
	)

	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		switch {
		case strings.HasPrefix(line, "portcullis_judge_latency_seconds_sum"):
			latencySum += lastFloat(line)
		case strings.HasPrefix(line, "portcullis_judge_latency_seconds_count"):
			latencyCount += lastFloat(line)
		case strings.HasPrefix(line, "portcullis_breaker_state"):
			if value := lastFloat(line); value > breakerMax {
				breakerMax = value
			}
		case strings.HasPrefix(line, "portcullis_judge_requests_total"):
			if judge := labelValue(line, "judge"); judge != "" {
				stats.judge = judge
			}
		}
	}

	if latencyCount > 0 {
		stats.meanLatency = time.Duration(latencySum / latencyCount * float64(time.Second))
		stats.hasLatency = true
	}
	switch breakerMax {
	case 0:
		stats.breaker = "closed"
	case 1:
		stats.breaker = "half_open"
	case 2:
		stats.breaker = "open"
	}
	return stats
}

// lastFloat parses the trailing number of a metrics line.
func lastFloat(line string) float64 {
	idx := strings.LastIndexByte(line, ' ')
	if idx < 0 {
		return 0
	}
	var value float64
	if _, err := fmt.Sscanf(strings.TrimSpace(line[idx+1:]), "%g", &value); err != nil {
		return 0
	}
	return value
}

// labelValue extracts a label's value from a metrics line.
func labelValue(line, label string) string {
	needle := label + "=\""
	idx := strings.Index(line, needle)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(needle):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// formatTTL renders the remaining lifetime compactly.
func formatTTL(until string, now time.Time) string {
	if until == "" || strings.HasPrefix(until, "0001-") {
		return "none"
	}
	parsed, err := time.Parse(time.RFC3339Nano, until)
	if err != nil {
		return until
	}
	remaining := parsed.Sub(now).Round(time.Minute)
	if remaining < 0 {
		return "expired"
	}
	return remaining.String()
}

// showDecisions prints recent decisions.
func (c *adminClient) showDecisions(limit int) error {
	decisions, err := c.fetchDecisions(limit)
	if err != nil {
		return err
	}

	//nolint:gocritic // decisionView is small and this runs once per decision
	for _, d := range decisions {
		fmt.Printf("%s %-24s %-22s %.2f -> %-9s (%s)\n",
			d.At.Format(time.RFC3339), d.Identity, d.Label, d.Confidence, d.Applied, d.Judge)
	}
	return nil
}

// setTier writes a manual tier.
func (c *adminClient) setTier(identity, tier string, ttl time.Duration) error {
	body := map[string]any{"tier": tier}
	if ttl > 0 {
		body["ttl"] = ttl.String()
	}

	var stored tierView
	if err := c.do(http.MethodPut, "/v1/admin/tiers/"+identity, body, &stored); err != nil {
		return err
	}

	fmt.Printf("%s -> %s (until %s)\n", stored.Identity, stored.Tier, stored.Until)
	return nil
}

// clearTier removes a tier.
func (c *adminClient) clearTier(identity string) error {
	if err := c.do(http.MethodDelete, "/v1/admin/tiers/"+identity, nil, nil); err != nil {
		return err
	}
	fmt.Printf("cleared %s\n", identity)
	return nil
}

// showMode prints the current judgment mode.
func (c *adminClient) showMode() error {
	mode, err := c.fetchMode()
	if err != nil {
		return err
	}
	fmt.Println(mode)
	return nil
}

// setMode changes the judgment mode.
func (c *adminClient) setMode(mode string) error {
	var resp modeResponse
	if err := c.do(http.MethodPut, "/v1/admin/config/mode", map[string]string{"mode": mode}, &resp); err != nil {
		return err
	}
	fmt.Println(resp.Mode)
	return nil
}

// fetchTiers reads the tier list.
func (c *adminClient) fetchTiers() ([]tierView, error) {
	var resp tierListResponse
	if err := c.do(http.MethodGet, "/v1/admin/tiers", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Tiers, nil
}

// fetchDecisions reads recent decisions.
func (c *adminClient) fetchDecisions(limit int) ([]decisionView, error) {
	var resp decisionListResponse
	if err := c.do(http.MethodGet, fmt.Sprintf("/v1/admin/decisions?limit=%d", limit), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Decisions, nil
}

// tierDecisionLookback is how far back to search for the decision that produced
// a tier before falling back to the identity's newest decision.
const tierDecisionLookback = 1000

// fetchTierDecision returns the decision that set a tier.
//
// The exact record is preferred, because an identity can be judged again later
// and a benign verdict does not de-escalate an active tier (guardrail G9). When
// the record has aged out of the ring, the newest decision for the identity is
// shown instead.
//
//nolint:gocritic // tierView is a small value copied once per lookup
func (c *adminClient) fetchTierDecision(tier tierView) (decisionView, bool) {
	var resp decisionListResponse
	query := fmt.Sprintf("/v1/admin/decisions?limit=%d&identity=%s",
		tierDecisionLookback, url.QueryEscape(tier.Identity))
	if err := c.do(http.MethodGet, query, nil, &resp); err != nil {
		return decisionView{}, false
	}
	if len(resp.Decisions) == 0 {
		return decisionView{}, false
	}

	if tier.DecisionID != "" {
		for _, d := range resp.Decisions {
			if d.ID == tier.DecisionID {
				return d, true
			}
		}
	}
	return resp.Decisions[0], true
}

// fetchMode reads the judgment mode.
func (c *adminClient) fetchMode() (string, error) {
	var resp modeResponse
	if err := c.do(http.MethodGet, "/v1/admin/config/mode", nil, &resp); err != nil {
		return "", err
	}
	return resp.Mode, nil
}

// do performs an admin request and decodes the response into out.
func (c *adminClient) do(method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	//nolint:gosec // the operator supplies the admin URL; calling it is the point
	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	//nolint:gosec // the operator supplies the admin URL; calling it is the point
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("admin request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("admin request %s %s failed: %s: %s",
			method, path, resp.Status, strings.TrimSpace(string(payload)))
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("failed to decode admin response: %w", err)
	}
	return nil
}
