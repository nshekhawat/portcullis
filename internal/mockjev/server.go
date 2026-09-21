// Package mockjev implements a fake TypeSafe System One server for the demo and
// the end-to-end tests, so both run with no API key.
//
// It speaks the same wire format as the real endpoint (spec §5.6): it validates
// the request shape, answers every Choice question with the offline rules judge,
// and spreads the probabilities the way a Choice answer is documented to look. It
// also injects the two things the demo needs to show: latency, and failures that
// can be switched on mid-run.
//
// A Server is built with New and served either in-process through Handler, or on
// its own listener through Start.
package mockjev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/judge/rules"
)

const (
	// systemOnePath is the evaluation endpoint the TypeSafe client posts to.
	systemOnePath = "/v1/systemone"
	// chaosPath flips the failure rate at runtime.
	chaosPath = "/chaos"
	// healthPath reports the current settings.
	healthPath = "/healthz"
	// questionChoice is the only question type mockjev answers.
	questionChoice = "choice"
	// maxChoiceOptions is the documented ceiling on a Choice rubric.
	maxChoiceOptions = 255
	// maxRequestBytes bounds a request body.
	maxRequestBytes = 1 << 20
	// spreadTemperature sharpens the rules judge's distribution into the
	// softmax-style spread a Choice answer carries.
	spreadTemperature = 0.9
	// probabilityFloor keeps every label in the distribution, because a Choice
	// answer is documented to report a probability for every option.
	probabilityFloor = 1e-6
	// tokensPerAnswer is the rough output-token cost of one Choice answer.
	tokensPerAnswer = 12
	// charsPerToken mirrors the client's estimate of one token per four bytes.
	charsPerToken = 4
	// fallbackModel is reported when a request does not name a model.
	fallbackModel = "jev-mock"
	// retryAfterSeconds is the delay mockjev asks a throttled client to wait.
	retryAfterSeconds = 1
)

// Config is the fake server's settings.
type Config struct {
	// Addr is the address Start listens on.
	Addr string
	// Latency is the artificial delay added to every answer.
	Latency time.Duration
	// Jitter is the uniform jitter applied around Latency.
	Jitter time.Duration
	// FailRate is the share of requests answered with StatusOnFail, in [0, 1].
	FailRate float64
	// StatusOnFail is the status returned for injected failures.
	StatusOnFail int
	// RateLimitRPM is the number of requests per minute before a 429, and zero
	// disables the limit.
	RateLimitRPM int
	// Logger receives the server's log lines. A nil Logger discards them.
	Logger *zap.Logger
}

// DefaultConfig returns the settings the mockjev command uses.
func DefaultConfig() Config {
	return Config{
		Addr:         ":8099",
		Latency:      120 * time.Millisecond,
		Jitter:       60 * time.Millisecond,
		FailRate:     0,
		StatusOnFail: http.StatusServiceUnavailable,
		RateLimitRPM: 1200,
	}
}

// validate checks the settings before anything is served.
func (c Config) validate() error {
	switch {
	case c.FailRate < 0 || c.FailRate > 1:
		return fmt.Errorf("fail-rate must be in [0, 1], got %g", c.FailRate)
	case c.StatusOnFail < 100 || c.StatusOnFail > 599:
		return fmt.Errorf("status-on-fail must be an HTTP status, got %d", c.StatusOnFail)
	case c.RateLimitRPM < 0:
		return fmt.Errorf("rate-limit-rpm must not be negative, got %d", c.RateLimitRPM)
	case c.Latency < 0 || c.Jitter < 0:
		return errors.New("latency and jitter must not be negative")
	}
	return nil
}

// Server is the fake TypeSafe System One endpoint. Its configuration is fixed at
// construction; the two things the demo changes at runtime — the chaos failure
// rate and the rate-limit window — sit behind mu.
type Server struct {
	judge        judge.Judge
	router       http.Handler
	httpServer   *http.Server
	addr         string
	latency      time.Duration
	jitter       time.Duration
	statusOnFail int
	rpm          int
	logger       *zap.Logger

	mu       sync.Mutex
	failRate float64
	limiter  limiter
}

// New returns a fake endpoint that decides with the offline rules judge, so the
// demo and e2e run with no API key and answer reproducibly. It rejects a config
// that cannot be served.
func New(cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	s := &Server{
		judge:        rules.New(),
		addr:         cfg.Addr,
		latency:      cfg.Latency,
		jitter:       cfg.Jitter,
		statusOnFail: cfg.StatusOnFail,
		rpm:          cfg.RateLimitRPM,
		logger:       logger,
		failRate:     cfg.FailRate,
		limiter:      limiter{rpm: cfg.RateLimitRPM},
	}

	s.router = s.routes()
	s.httpServer = &http.Server{
		Addr:              cfg.Addr,
		Handler:           logging(zap.NewStdLog(logger), s.router),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

// Handler returns the mockjev routes, for serving the fake in-process: an
// httptest server, for example. It does not log; Start adds the request log.
func (s *Server) Handler() http.Handler {
	return s.router
}

// Start listens on the configured address and serves until Shutdown is called. It
// returns nil once the server has shut down cleanly.
func (s *Server) Start() error {
	health := s.health()
	s.logger.Info(fmt.Sprintf("listening on %s latency=%s jitter=%s fail-rate=%g status-on-fail=%d rate-limit-rpm=%d",
		s.addr, health.Latency, health.Jitter, health.FailRate, health.StatusOnFail, health.RateLimitRPM))

	if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown stops the listener and waits for in-flight requests, until ctx is
// done. It is safe to call on a server Start was never asked to serve.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down")
	return s.httpServer.Shutdown(ctx)
}

// SetFailRate replaces the chaos failure rate, which is what the outage demo
// drives.
func (s *Server) SetFailRate(rate float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failRate = rate
}

// routes builds the mockjev routes. Method patterns make a wrong method a 405
// instead of a silent match.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+systemOnePath, s.handleSystemOne)
	mux.HandleFunc("POST "+chaosPath, s.handleChaos)
	mux.HandleFunc("GET "+healthPath, s.handleHealth)
	return mux
}

// wireRequest is the System One request body, the same wire format the Portcullis
// client sends. mockjev keeps its own copy of the types on purpose: a fake that
// shared the client's types could not catch a wire change.
type wireRequest struct {
	Model     string                  `json:"model"`
	State     *wireState              `json:"state"`
	Questions map[string]wireQuestion `json:"questions"`
}

// wireState is the content handed to the model.
type wireState struct {
	Context  string        `json:"context"`
	Suspects []wireSuspect `json:"suspects"`
}

// wireSuspect is one bucketed suspect. It carries no identity: the gateway never
// sends one, and mockjev has nothing to reconstruct it from.
type wireSuspect struct {
	ID               string   `json:"id"`
	RequestRate      string   `json:"request_rate"`
	TimingRegularity string   `json:"timing_regularity"`
	RouteDiversity   string   `json:"route_diversity"`
	DeniedShare      string   `json:"denied_share"`
	AuthFailShare    string   `json:"auth_fail_share"`
	NotFoundShare    string   `json:"not_found_share"`
	ServerErrorShare string   `json:"server_error_share"`
	Methods          string   `json:"methods"`
	ClientFamily     string   `json:"client_family"`
	Evidence         []string `json:"evidence"`
	SampledPaths     []string `json:"sampled_paths"`
}

// wireQuestion is one typed question. Instructions may be a string, an object, or
// an array, and a rubric value may be a string, an object, an array, or null, so
// both are kept raw.
type wireQuestion struct {
	Type         string                     `json:"type"`
	Instructions json.RawMessage            `json:"instructions"`
	Criteria     map[string]json.RawMessage `json:"criteria"`
}

// wireResponse is the System One response envelope.
type wireResponse struct {
	Model   string                `json:"model"`
	Answers map[string]wireAnswer `json:"answers"`
	Usage   wireUsage             `json:"usage"`
}

// wireAnswer is one Choice answer.
type wireAnswer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice"`
	Probabilities map[string]float64 `json:"probabilities"`
	Confidence    float64            `json:"confidence"`
}

// wireUsage is the token accounting of one response.
type wireUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// wireError is the body of every failure response.
type wireError struct {
	Error string `json:"error"`
}

// wireHealth is the GET /healthz body, and the acknowledgement POST /chaos
// returns.
type wireHealth struct {
	Status       string  `json:"status"`
	FailRate     float64 `json:"fail_rate"`
	Latency      string  `json:"latency"`
	Jitter       string  `json:"jitter"`
	StatusOnFail int     `json:"status_on_fail"`
	RateLimitRPM int     `json:"rate_limit_rpm"`
}

// wireChaos is the POST /chaos body.
type wireChaos struct {
	FailRate *float64 `json:"fail_rate"`
}

// handleSystemOne validates the request shape, then answers with the rules judge.
func (s *Server) handleSystemOne(w http.ResponseWriter, r *http.Request) {
	if !s.allow(time.Now()) {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
		writeJSON(w, http.StatusTooManyRequests, wireError{Error: "rate limit exceeded"})
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, wireError{Error: "unreadable body: " + err.Error()})
		return
	}

	var req wireRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, wireError{Error: "invalid json body: " + err.Error()})
		return
	}
	if err := validateRequest(&req, r.Header.Get("Authorization")); err != nil {
		writeJSON(w, http.StatusBadRequest, wireError{Error: err.Error()})
		return
	}

	if err := s.delay(r.Context()); err != nil {
		return // the client gave up while we were pretending to think
	}
	if s.injectedFailure() {
		writeJSON(w, s.statusOnFail, wireError{Error: "injected failure"})
		return
	}

	writeJSON(w, http.StatusOK, s.answer(&req, len(body)))
}

// handleChaos flips the failure rate at runtime, which is what the outage demo
// drives.
func (s *Server) handleChaos(w http.ResponseWriter, r *http.Request) {
	var req wireChaos
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, wireError{Error: "invalid json body: " + err.Error()})
		return
	}
	if req.FailRate == nil {
		writeJSON(w, http.StatusBadRequest, wireError{Error: "fail_rate is required"})
		return
	}
	if *req.FailRate < 0 || *req.FailRate > 1 {
		writeJSON(w, http.StatusBadRequest, wireError{Error: "fail_rate must be in [0, 1]"})
		return
	}

	s.SetFailRate(*req.FailRate)
	writeJSON(w, http.StatusOK, s.health())
}

// handleHealth reports the settings the demo prints.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.health())
}

// validateRequest checks the request shape the client contract requires: a bearer
// token, a present state, and a Choice question whose rubric holds 1-255 options
// (spec §5.6). It never looks at feature values, which are the model's business.
func validateRequest(req *wireRequest, authorization string) error {
	if !bearerToken(authorization) {
		return errors.New("missing bearer token")
	}
	if req.State == nil {
		return errors.New("state is required")
	}
	for _, id := range sortedQuestionIDs(req.Questions) {
		q := req.Questions[id]
		if q.Type != questionChoice {
			return fmt.Errorf("question %q: type must be %q, got %q", id, questionChoice, q.Type)
		}
		if len(q.Criteria) < 1 || len(q.Criteria) > maxChoiceOptions {
			return fmt.Errorf("question %q: criteria must hold 1-%d options, got %d", id, maxChoiceOptions, len(q.Criteria))
		}
	}
	return nil
}

// bearerToken reports whether the Authorization header carries a non-empty bearer
// token.
func bearerToken(authorization string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(authorization, prefix) {
		return false
	}
	return strings.TrimSpace(strings.TrimPrefix(authorization, prefix)) != ""
}

// sortedQuestionIDs returns the question ids in ascending order, so a validation
// error names the same question on every run.
func sortedQuestionIDs(questions map[string]wireQuestion) []string {
	ids := make([]string, 0, len(questions))
	for id := range questions {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// answer builds one response: a Choice answer for every suspect that also has a
// question, decided by the offline rules judge.
func (s *Server) answer(req *wireRequest, requestBytes int) wireResponse {
	verdicts, err := s.judge.Judge(context.Background(), suspectsOf(req.State.Suspects))
	if err != nil {
		// The rules judge only fails on a canceled context, and this context is
		// never canceled: an empty answer set is the honest response.
		verdicts = nil
	}
	byID := make(map[string]judge.Verdict, len(verdicts))
	for i := range verdicts {
		byID[verdicts[i].SuspectID] = verdicts[i]
	}

	answers := make(map[string]wireAnswer, len(byID))
	for i := range req.State.Suspects {
		suspect := &req.State.Suspects[i]
		verdict, ok := byID[suspect.ID]
		if !ok {
			continue
		}
		if _, asked := req.Questions[suspect.ID]; !asked {
			continue
		}
		answers[suspect.ID] = wireAnswer{
			Type:          questionChoice,
			Choice:        string(verdict.Label),
			Probabilities: spread(verdict.Probabilities),
			Confidence:    verdict.Confidence,
		}
	}

	model := req.Model
	if model == "" {
		model = fallbackModel
	}
	return wireResponse{
		Model:   model,
		Answers: answers,
		Usage: wireUsage{
			InputTokens:  requestBytes / charsPerToken,
			OutputTokens: len(answers) * tokensPerAnswer,
		},
	}
}

// suspectsOf converts a wire state into detector suspects: only the bucketed
// features and evidence travel, so there is no identity to reconstruct.
func suspectsOf(in []wireSuspect) []detect.Suspect {
	out := make([]detect.Suspect, 0, len(in))
	for i := range in {
		s := &in[i]
		out = append(out, detect.Suspect{
			SuspectID: s.ID,
			Evidence:  s.Evidence,
			Features: detect.SemanticFeatures{
				RequestRate:      s.RequestRate,
				TimingRegularity: s.TimingRegularity,
				RouteDiversity:   s.RouteDiversity,
				DeniedShare:      s.DeniedShare,
				AuthFailShare:    s.AuthFailShare,
				NotFoundShare:    s.NotFoundShare,
				ServerErrorShare: s.ServerErrorShare,
				Methods:          s.Methods,
				ClientFamily:     s.ClientFamily,
				SampledPaths:     s.SampledPaths,
			},
		})
	}
	return out
}

// spread turns the rules judge's probabilities into the softmax-style
// distribution a Choice answer carries: the log-probabilities are the logits,
// scaled by spreadTemperature, which sharpens the distribution around the chosen
// label. It is deterministic, so the demo and e2e print the same numbers on every
// run, and every label keeps a probability.
func spread(probabilities map[judge.Label]float64) map[string]float64 {
	labels := judge.Labels()
	logits := make([]float64, len(labels))
	names := make([]string, len(labels))

	peak := math.Inf(-1)
	for i, label := range labels {
		p, ok := probabilities[label]
		if !ok || p <= probabilityFloor {
			p = probabilityFloor
		}
		logits[i] = math.Log(p) / spreadTemperature
		names[i] = string(label)
		if logits[i] > peak {
			peak = logits[i]
		}
	}

	var total float64
	for i := range logits {
		logits[i] = math.Exp(logits[i] - peak)
		total += logits[i]
	}

	out := make(map[string]float64, len(names))
	for i, name := range names {
		out[name] = logits[i] / total
	}
	return out
}

// delay sleeps the configured latency and jitter, and gives up as soon as the
// client goes away.
func (s *Server) delay(ctx context.Context) error {
	latency := s.latency
	if s.jitter > 0 {
		//nolint:gosec // timing jitter for a fake server, not a security decision
		latency += time.Duration((rand.Float64()*2 - 1) * float64(s.jitter))
	}
	if latency <= 0 {
		return nil
	}

	timer := time.NewTimer(latency)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// injectedFailure reports whether this request should fail, per the chaos rate.
func (s *Server) injectedFailure() bool {
	s.mu.Lock()
	rate := s.failRate
	s.mu.Unlock()

	switch {
	case rate <= 0:
		return false
	case rate >= 1:
		return true
	default:
		//nolint:gosec // deciding whether a fake fails is not a security decision
		return rand.Float64() < rate
	}
}

// health reports the current settings.
func (s *Server) health() wireHealth {
	s.mu.Lock()
	defer s.mu.Unlock()
	return wireHealth{
		Status:       "ok",
		FailRate:     s.failRate,
		Latency:      s.latency.String(),
		Jitter:       s.jitter.String(),
		StatusOnFail: s.statusOnFail,
		RateLimitRPM: s.rpm,
	}
}

// allow applies the rate limit, so the demo and e2e exercise the client's 429
// path with the header shape the real API uses.
func (s *Server) allow(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.limiter.allow(now)
}

// limiter counts requests in a fixed one-minute window.
type limiter struct {
	rpm   int
	start time.Time
	count int
}

// allow reports whether one more request fits in the current window. A zero rpm
// disables the limit.
func (l *limiter) allow(now time.Time) bool {
	if l.rpm <= 0 {
		return true
	}
	if l.start.IsZero() || now.Sub(l.start) >= time.Minute {
		l.start = now
		l.count = 0
	}
	if l.count >= l.rpm {
		return false
	}
	l.count++
	return true
}

// writeJSON writes one JSON response.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// logging wraps a handler and logs one line per request. It logs no caller, no
// body, and no header.
func logging(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		logger.Printf("%s %s %d %s", r.Method, r.URL.Path, recorder.status, time.Since(start).Round(time.Millisecond))
	})
}

// statusRecorder remembers the status a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader records the status before writing it.
func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}
