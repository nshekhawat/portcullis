package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/controller"
	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/signals"
	"github.com/nshekhawat/portcullis/internal/storage"
)

// recordingSignals captures observations so tests can assert what the request
// path handed to the signals pipeline.
type recordingSignals struct {
	mu  sync.Mutex
	obs []signals.Observation
}

func (r *recordingSignals) Record(o signals.Observation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.obs = append(r.obs, o)
}

func (r *recordingSignals) observations() []signals.Observation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]signals.Observation(nil), r.obs...)
}

// stubMode is a ModeController the tests can drive without standing up a full
// controller.
type stubMode struct {
	mu   sync.Mutex
	mode controller.Mode
}

func newStubMode(mode controller.Mode) *stubMode { return &stubMode{mode: mode} }

func (m *stubMode) Mode() controller.Mode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

func (m *stubMode) SetMode(mode controller.Mode) error {
	if _, err := parseMode(string(mode)); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mode = mode
	return nil
}

// newAdminHTTPServer builds a server with the admin dependencies wired.
func newAdminHTTPServer(t *testing.T, tiers policy.TierStore, audit *controller.AuditRing, mode ModeController, rec signals.Recorder) *HTTPServer {
	t.Helper()

	store := storage.NewMemoryStorage(time.Minute)
	t.Cleanup(func() { _ = store.Close() })

	return NewHTTPServer(newTestLimiter(store), store, &HTTPConfig{
		Port:        8080,
		AdminTokens: []string{testAdminToken},
		Tiers:       tiers,
		Audit:       audit,
		Mode:        mode,
		Signals:     rec,
		TierConfigs: map[policy.Tier]policy.TierConfig{
			policy.TierThrottle: {Multiplier: 0.25, TTL: 15 * time.Minute},
			policy.TierBlock:    {TTL: 60 * time.Minute},
		},
		MaxTTL: 24 * time.Hour,
	}, nil)
}

// adminJSON performs an authenticated admin request with an optional JSON body.
func adminJSON(t *testing.T, server *HTTPServer, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Buffer
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewBuffer(raw)
	} else {
		reader = bytes.NewBuffer(nil)
	}

	req, err := http.NewRequest(method, target, reader)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.Engine().ServeHTTP(w, req)
	return w
}

// decodeTiers reads the tier list response.
func decodeTiers(t *testing.T, w *httptest.ResponseRecorder) []tierView {
	t.Helper()

	var resp struct {
		Tiers []tierView `json:"tiers"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp.Tiers
}

func TestAdminTiers_CRUD(t *testing.T) {
	tiers := policy.NewMemoryStore(nil)
	server := newAdminHTTPServer(t, tiers, nil, nil, nil)

	const identity = "203.0.113.9"

	t.Run("set stores a manual entry", func(t *testing.T) {
		w := adminJSON(t, server, http.MethodPut, "/v1/admin/tiers/"+identity, map[string]string{
			"tier":   "throttle",
			"ttl":    "15m",
			"reason": "manual review",
		})
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var got tierView
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		assert.Equal(t, identity, got.Identity)
		assert.Equal(t, "throttle", got.Tier)
		assert.Equal(t, "manual", got.Source)
		assert.WithinDuration(t, time.Now().Add(15*time.Minute), got.Until, time.Minute)
	})

	t.Run("get lists the entry", func(t *testing.T) {
		w := adminJSON(t, server, http.MethodGet, "/v1/admin/tiers", nil)
		require.Equal(t, http.StatusOK, w.Code)

		got := decodeTiers(t, w)
		require.Len(t, got, 1)
		assert.Equal(t, identity, got[0].Identity)
		assert.Equal(t, "throttle", got[0].Tier)
	})

	t.Run("delete removes the entry", func(t *testing.T) {
		w := adminJSON(t, server, http.MethodDelete, "/v1/admin/tiers/"+identity, nil)
		assert.Equal(t, http.StatusNoContent, w.Code)

		w = adminJSON(t, server, http.MethodGet, "/v1/admin/tiers", nil)
		require.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, decodeTiers(t, w))
	})

	t.Run("delete is idempotent", func(t *testing.T) {
		w := adminJSON(t, server, http.MethodDelete, "/v1/admin/tiers/"+identity, nil)
		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("unknown tier is rejected", func(t *testing.T) {
		w := adminJSON(t, server, http.MethodPut, "/v1/admin/tiers/"+identity, map[string]string{
			"tier": "banana",
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)

		_, ok := tiers.Lookup(identity, time.Now())
		assert.False(t, ok, "a rejected tier must not be stored")
	})

	t.Run("invalid ttl is rejected", func(t *testing.T) {
		w := adminJSON(t, server, http.MethodPut, "/v1/admin/tiers/"+identity, map[string]string{
			"tier": "watch",
			"ttl":  "soon",
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	// L8: setTierHandler took c.Param("identity") unvalidated and wrote it
	// straight into the tier store, unlike the check path (ValidateKey,
	// B20). An over-long identity would be admitted into the shared store
	// (Redis, in a real deployment) with no bound.
	t.Run("an over-long identity is rejected", func(t *testing.T) {
		tooLong := strings.Repeat("a", ratelimiter.MaxIdentifierLength+1)
		w := adminJSON(t, server, http.MethodPut, "/v1/admin/tiers/"+tooLong, map[string]string{
			"tier": "watch",
		})
		assert.Equal(t, http.StatusBadRequest, w.Code)

		_, ok := tiers.Lookup(tooLong, time.Now())
		assert.False(t, ok, "a rejected identity must not be stored")
	})
}

// TestAdminTiers_TTLResolution verifies the request TTL, the configured tier
// TTL, and the configured cap, in that order.
func TestAdminTiers_TTLResolution(t *testing.T) {
	tiers := policy.NewMemoryStore(nil)
	server := newAdminHTTPServer(t, tiers, nil, nil, nil)

	untilFor := func(t *testing.T, body map[string]string) time.Duration {
		t.Helper()
		w := adminJSON(t, server, http.MethodPut, "/v1/admin/tiers/ttl-probe", body)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var got tierView
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		return time.Until(got.Until)
	}

	t.Run("omitted ttl uses the configured tier ttl", func(t *testing.T) {
		got := untilFor(t, map[string]string{"tier": "throttle"})
		assert.InDelta(t, (15 * time.Minute).Seconds(), got.Seconds(), 60)
	})

	t.Run("requested ttl wins", func(t *testing.T) {
		got := untilFor(t, map[string]string{"tier": "throttle", "ttl": "2m"})
		assert.InDelta(t, (2 * time.Minute).Seconds(), got.Seconds(), 60)
	})

	t.Run("ttl is capped by max_ttl", func(t *testing.T) {
		got := untilFor(t, map[string]string{"tier": "block", "ttl": "72h"})
		assert.InDelta(t, (24 * time.Hour).Seconds(), got.Seconds(), 60)
	})
}

func TestAdminTiers_ClearAll(t *testing.T) {
	tiers := policy.NewMemoryStore(nil)
	server := newAdminHTTPServer(t, tiers, nil, nil, nil)

	seed := func(t *testing.T) {
		t.Helper()
		for _, id := range []string{"a", "b", "c"} {
			w := adminJSON(t, server, http.MethodPut, "/v1/admin/tiers/"+id, map[string]string{"tier": "watch"})
			require.Equal(t, http.StatusOK, w.Code)
		}
	}

	seed(t)

	t.Run("missing confirmation header is refused", func(t *testing.T) {
		w := adminJSON(t, server, http.MethodDelete, "/v1/admin/tiers?all=true", nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		w = adminJSON(t, server, http.MethodGet, "/v1/admin/tiers", nil)
		require.Len(t, decodeTiers(t, w), 3, "a refused clear must not delete anything")
	})

	t.Run("missing all=true is refused", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodDelete, "/v1/admin/tiers", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
		req.Header.Set(allConfirmHeader, allConfirmValue)

		w := httptest.NewRecorder()
		server.Engine().ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		w = adminJSON(t, server, http.MethodGet, "/v1/admin/tiers", nil)
		require.Len(t, decodeTiers(t, w), 3)
	})

	t.Run("confirmed clear empties the store", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodDelete, "/v1/admin/tiers?all=true", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
		req.Header.Set(allConfirmHeader, allConfirmValue)

		w := httptest.NewRecorder()
		server.Engine().ServeHTTP(w, req)
		require.Equal(t, http.StatusNoContent, w.Code)

		w = adminJSON(t, server, http.MethodGet, "/v1/admin/tiers", nil)
		assert.Empty(t, decodeTiers(t, w))
	})
}

func TestAdminDecisions_Filtering(t *testing.T) {
	audit := controller.NewAuditRing(1500)
	server := newAdminHTTPServer(t, nil, audit, nil, nil)

	audit.Add(controller.DecisionRecord{ID: "d1", At: time.Unix(100, 0), Identity: "alpha", Label: judge.LabelScraper})
	audit.Add(controller.DecisionRecord{ID: "d2", At: time.Unix(200, 0), Identity: "beta", Label: judge.LabelL7Flood})
	audit.Add(controller.DecisionRecord{ID: "d3", At: time.Unix(300, 0), Identity: "alpha", Label: judge.LabelScraper})

	type decisionsResponse struct {
		Decisions []controller.DecisionRecord `json:"decisions"`
	}

	list := func(t *testing.T, query string) decisionsResponse {
		t.Helper()
		w := adminJSON(t, server, http.MethodGet, "/v1/admin/decisions"+query, nil)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var resp decisionsResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		return resp
	}

	t.Run("newest first", func(t *testing.T) {
		resp := list(t, "")
		require.Len(t, resp.Decisions, 3)
		assert.Equal(t, []string{"d3", "d2", "d1"}, []string{resp.Decisions[0].ID, resp.Decisions[1].ID, resp.Decisions[2].ID})
	})

	t.Run("identity filter", func(t *testing.T) {
		resp := list(t, "?identity=alpha")
		require.Len(t, resp.Decisions, 2)
		for _, rec := range resp.Decisions {
			assert.Equal(t, "alpha", rec.Identity)
		}
	})

	t.Run("label filter", func(t *testing.T) {
		resp := list(t, "?label=l7_flood")
		require.Len(t, resp.Decisions, 1)
		assert.Equal(t, "d2", resp.Decisions[0].ID)
	})

	t.Run("limit", func(t *testing.T) {
		resp := list(t, "?limit=1")
		require.Len(t, resp.Decisions, 1)
		assert.Equal(t, "d3", resp.Decisions[0].ID)
	})

	t.Run("invalid limit is rejected", func(t *testing.T) {
		w := adminJSON(t, server, http.MethodGet, "/v1/admin/decisions?limit=lots", nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("default limit is 100", func(t *testing.T) {
		for i := 0; i < 150; i++ {
			audit.Add(controller.DecisionRecord{ID: fmt.Sprintf("bulk-%d", i), Identity: "bulk"})
		}
		resp := list(t, "?identity=bulk")
		assert.Len(t, resp.Decisions, 100)
	})

	t.Run("limit is capped at 1000", func(t *testing.T) {
		for i := 0; i < 1200; i++ {
			audit.Add(controller.DecisionRecord{ID: fmt.Sprintf("cap-%d", i), Identity: "cap"})
		}
		resp := list(t, "?limit=5000")
		assert.Len(t, resp.Decisions, 1000)
	})
}

func TestAdminMode(t *testing.T) {
	mode := newStubMode(controller.ModeShadow)
	server := newAdminHTTPServer(t, nil, nil, mode, nil)

	readMode := func(t *testing.T) string {
		t.Helper()
		w := adminJSON(t, server, http.MethodGet, "/v1/admin/config/mode", nil)
		require.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Mode string `json:"mode"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		return resp.Mode
	}

	t.Run("get returns the current mode", func(t *testing.T) {
		assert.Equal(t, "shadow", readMode(t))
	})

	t.Run("put changes the mode", func(t *testing.T) {
		w := adminJSON(t, server, http.MethodPut, "/v1/admin/config/mode", map[string]string{"mode": "enforce"})
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var resp struct {
			Mode string `json:"mode"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "enforce", resp.Mode)
		assert.Equal(t, "enforce", readMode(t))
	})

	t.Run("unknown mode is rejected", func(t *testing.T) {
		w := adminJSON(t, server, http.MethodPut, "/v1/admin/config/mode", map[string]string{"mode": "yolo"})
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "enforce", readMode(t), "a rejected mode change must not stick")
	})

	t.Run("malformed body is rejected", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPut, "/v1/admin/config/mode", bytes.NewBufferString("{"))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		server.Engine().ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestReport(t *testing.T) {
	rec := &recordingSignals{}
	server := newAdminHTTPServer(t, nil, nil, nil, rec)

	post := func(t *testing.T, server *HTTPServer, body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(body)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodPost, "/v1/report", bytes.NewBuffer(raw))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		server.Engine().ServeHTTP(w, req)
		return w
	}

	t.Run("accepts and records", func(t *testing.T) {
		w := post(t, server, ReportRequest{
			Identifier: "api-key-7",
			Resource:   "/v1/items",
			Status:     200,
			Path:       "/v1/items?page=2",
			Method:     "GET",
			UserAgent:  "curl/8.4.0",
		})
		require.Equal(t, http.StatusAccepted, w.Code)

		var resp map[string]bool
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp["accepted"])

		obs := rec.observations()
		require.Len(t, obs, 1)
		assert.Equal(t, "api-key-7", obs[0].Identity)
		assert.Equal(t, "/v1/items", obs[0].Route)
		assert.Equal(t, "/v1/items?page=2", obs[0].Path)
		assert.Equal(t, "GET", obs[0].Method)
		assert.Equal(t, 200, obs[0].Status)
		assert.Equal(t, signals.UACurl, obs[0].UAFamily)
		assert.True(t, obs[0].Allowed, "a reported request was already served, so it counts as allowed")
	})

	t.Run("missing identifier is rejected", func(t *testing.T) {
		w := post(t, server, ReportRequest{Resource: "x"})
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("body is limited", func(t *testing.T) {
		limited := newAdminHTTPServer(t, nil, nil, nil, nil)
		limited.config.MaxBodyBytes = 64

		w := post(t, limited, ReportRequest{Identifier: string(bytes.Repeat([]byte("x"), 200))})
		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	})

	t.Run("works without a signals recorder", func(t *testing.T) {
		w := post(t, newAdminHTTPServer(t, nil, nil, nil, nil), ReportRequest{Identifier: "lonely"})
		assert.Equal(t, http.StatusAccepted, w.Code)
	})
}

// TestCheck_Attributes verifies the optional attributes object reaches the
// signals pipeline without changing the decision.
func TestCheck_Attributes(t *testing.T) {
	rec := &recordingSignals{}
	server := newAdminHTTPServer(t, nil, nil, nil, rec)

	post := func(t *testing.T, req CheckRequest) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(req)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		httpReq, err := http.NewRequest(http.MethodPost, "/v1/check", bytes.NewBuffer(raw))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/json")
		server.Engine().ServeHTTP(w, httpReq)
		return w
	}

	t.Run("attributes are recorded", func(t *testing.T) {
		w := post(t, CheckRequest{
			Identifier: "attrs-user",
			Resource:   "/v1/items",
			Tokens:     1,
			Attributes: &Attributes{Path: "/v1/items/42", Method: "POST", UserAgent: "python-requests/2.31"},
		})
		require.Equal(t, http.StatusOK, w.Code)

		obs := rec.observations()
		require.Len(t, obs, 1)
		assert.Equal(t, "attrs-user", obs[0].Identity)
		assert.Equal(t, "/v1/items", obs[0].Route)
		assert.Equal(t, "/v1/items/42", obs[0].Path)
		assert.Equal(t, "POST", obs[0].Method)
		assert.Equal(t, signals.UAPython, obs[0].UAFamily)
		assert.True(t, obs[0].Allowed)
	})

	t.Run("absent attributes record nothing", func(t *testing.T) {
		before := len(rec.observations())
		w := post(t, CheckRequest{Identifier: "no-attrs", Tokens: 1})
		require.Equal(t, http.StatusOK, w.Code)
		assert.Len(t, rec.observations(), before)
	})

	t.Run("denied checks are recorded as denied", func(t *testing.T) {
		// capacity is 10
		for i := 0; i < 10; i++ {
			require.Equal(t, http.StatusOK, post(t, CheckRequest{
				Identifier: "attrs-denied",
				Tokens:     1,
				Attributes: &Attributes{Path: "/x", Method: "GET", UserAgent: "curl/8"},
			}).Code)
		}

		w := post(t, CheckRequest{
			Identifier: "attrs-denied",
			Tokens:     1,
			Attributes: &Attributes{Path: "/x", Method: "GET", UserAgent: "curl/8"},
		})
		require.Equal(t, http.StatusTooManyRequests, w.Code)

		obs := rec.observations()
		last := obs[len(obs)-1]
		assert.Equal(t, "attrs-denied", last.Identity)
		assert.False(t, last.Allowed)
	})
}

// TestAdmin_Unauthorized401NewRoutes verifies every route added by the admin
// API is closed without a valid bearer token.
func TestAdmin_Unauthorized401NewRoutes(t *testing.T) {
	server := newAdminHTTPServer(t, policy.NewMemoryStore(nil), controller.NewAuditRing(10), newStubMode(controller.ModeShadow), &recordingSignals{})

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/admin/tiers"},
		{http.MethodPut, "/v1/admin/tiers/203.0.113.9"},
		{http.MethodDelete, "/v1/admin/tiers/203.0.113.9"},
		{http.MethodDelete, "/v1/admin/tiers?all=true"},
		{http.MethodGet, "/v1/admin/decisions"},
		{http.MethodGet, "/v1/admin/config/mode"},
		{http.MethodPut, "/v1/admin/config/mode"},
	}

	cases := []struct {
		name   string
		header string
	}{
		{"no token", ""},
		{"malformed header", "token-without-scheme"},
		{"wrong token", "Bearer wrong-token"},
	}

	for _, ep := range endpoints {
		for _, tc := range cases {
			t.Run(ep.method+" "+ep.path+" "+tc.name, func(t *testing.T) {
				req, err := http.NewRequest(ep.method, ep.path, bytes.NewBufferString(`{"tier":"watch","mode":"enforce"}`))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")
				if tc.header != "" {
					req.Header.Set("Authorization", tc.header)
				}

				w := httptest.NewRecorder()
				server.Engine().ServeHTTP(w, req)
				assert.Equal(t, http.StatusUnauthorized, w.Code)
			})
		}
	}
}

// TestAdmin_MissingDependencies503 verifies the admin API degrades to 503
// rather than panicking when a dependency was never wired.
func TestAdmin_MissingDependencies503(t *testing.T) {
	server := newAdminHTTPServer(t, nil, nil, nil, nil)

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/admin/tiers"},
		{http.MethodPut, "/v1/admin/tiers/x"},
		{http.MethodDelete, "/v1/admin/tiers/x"},
		{http.MethodDelete, "/v1/admin/tiers?all=true"},
		{http.MethodGet, "/v1/admin/decisions"},
		{http.MethodGet, "/v1/admin/config/mode"},
		{http.MethodPut, "/v1/admin/config/mode"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			w := adminJSON(t, server, ep.method, ep.path, map[string]string{"tier": "watch", "mode": "enforce"})
			assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		})
	}
}
