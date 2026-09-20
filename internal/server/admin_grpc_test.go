package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/nshekhawat/portcullis/api/proto/portcullis/v1"
	"github.com/nshekhawat/portcullis/internal/controller"
	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/storage"
)

// adminGRPCHarness bundles a running server with its admin dependencies.
type adminGRPCHarness struct {
	admin   pb.AdminServiceClient
	limiter pb.RateLimiterServiceClient
	tiers   *policy.MemoryStore
	audit   *controller.AuditRing
	signals *recordingSignals
}

// newAdminGRPCHarness starts a gRPC server on a random port. mutate may adjust
// the config before the server is built, which is how the missing-dependency
// cases are exercised.
func newAdminGRPCHarness(t *testing.T, mutate func(*GRPCConfig)) *adminGRPCHarness {
	t.Helper()

	store := storage.NewMemoryStorage(time.Minute)
	limiter := ratelimiter.NewRateLimiter(store, &ratelimiter.Config{
		KeyPrefix: "test:",
		DefaultRule: &ratelimiter.Rule{
			Name:       "default",
			Capacity:   10,
			RefillRate: 0.1,
		},
		TTL: time.Hour,
	}, nil)

	h := &adminGRPCHarness{
		tiers:   policy.NewMemoryStore(nil),
		audit:   controller.NewAuditRing(100),
		signals: &recordingSignals{},
	}

	cfg := &GRPCConfig{
		Port:              0,
		MaxRecvMsgSize:    4 * 1024 * 1024,
		MaxSendMsgSize:    4 * 1024 * 1024,
		EnableReflection:  false,
		EnableHealthCheck: false,
		AdminTokens:       []string{testGRPCToken},
		Tiers:             h.tiers,
		Audit:             h.audit,
		Signals:           h.signals,
		TierConfigs: map[policy.Tier]policy.TierConfig{
			policy.TierThrottle: {Multiplier: 0.25, TTL: 15 * time.Minute},
			policy.TierBlock:    {TTL: 60 * time.Minute},
		},
		MaxTTL: 24 * time.Hour,
	}
	if mutate != nil {
		mutate(cfg)
	}

	server := NewGRPCServer(limiter, cfg, nil)

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	go func() { _ = server.server.Serve(listener) }()

	conn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = conn.Close()
		server.Stop()
		_ = store.Close()
	})

	h.admin = pb.NewAdminServiceClient(conn)
	h.limiter = pb.NewRateLimiterServiceClient(conn)
	return h
}

// wrongTokenCtx carries a bearer token the server does not accept.
func wrongTokenCtx() context.Context {
	return metadata.NewOutgoingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer wrong-token"),
	)
}

// TestGRPCAdmin_Auth verifies every AdminService RPC is closed without an
// accepted bearer token and open with one.
func TestGRPCAdmin_Auth(t *testing.T) {
	h := newAdminGRPCHarness(t, nil)

	calls := []struct {
		name string
		call func(ctx context.Context) error
	}{
		{"SetTier", func(ctx context.Context) error {
			_, err := h.admin.SetTier(ctx, &pb.SetTierRequest{Identity: "auth-probe", Tier: "watch"})
			return err
		}},
		{"ClearTier", func(ctx context.Context) error {
			_, err := h.admin.ClearTier(ctx, &pb.ClearTierRequest{Identity: "auth-probe"})
			return err
		}},
		{"ListTiers", func(ctx context.Context) error {
			_, err := h.admin.ListTiers(ctx, &pb.ListTiersRequest{})
			return err
		}},
		{"ListDecisions", func(ctx context.Context) error {
			_, err := h.admin.ListDecisions(ctx, &pb.ListDecisionsRequest{})
			return err
		}},
	}

	for _, tc := range calls {
		t.Run(tc.name+" without token", func(t *testing.T) {
			err := tc.call(context.Background())
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.Unauthenticated, st.Code())
		})

		t.Run(tc.name+" with wrong token", func(t *testing.T) {
			err := tc.call(wrongTokenCtx())
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.Unauthenticated, st.Code())
		})

		t.Run(tc.name+" with token", func(t *testing.T) {
			require.NoError(t, tc.call(adminCtx()))
		})
	}
}

func TestGRPCAdmin_TierCRUD(t *testing.T) {
	h := newAdminGRPCHarness(t, nil)
	ctx := adminCtx()

	const identity = "198.51.100.4"

	set, err := h.admin.SetTier(ctx, &pb.SetTierRequest{
		Identity:   identity,
		Tier:       "throttle",
		TtlSeconds: 600,
		Reason:     "manual review",
	})
	require.NoError(t, err)
	assert.Equal(t, identity, set.Identity)
	assert.Equal(t, "throttle", set.Tier)
	assert.Equal(t, "manual", set.Source)
	assert.InDelta(t, time.Now().Add(10*time.Minute).Unix(), set.UntilUnix, 60)

	listed, err := h.admin.ListTiers(ctx, &pb.ListTiersRequest{})
	require.NoError(t, err)
	require.Len(t, listed.Tiers, 1)
	assert.Equal(t, identity, listed.Tiers[0].Identity)
	assert.Equal(t, "throttle", listed.Tiers[0].Tier)

	// The stored entry is the same one the data plane would read.
	entry, ok := h.tiers.Lookup(identity, time.Now())
	require.True(t, ok)
	assert.Equal(t, policy.TierThrottle, entry.Tier)
	assert.Equal(t, "manual", entry.Source)

	cleared, err := h.admin.ClearTier(ctx, &pb.ClearTierRequest{Identity: identity})
	require.NoError(t, err)
	assert.True(t, cleared.Cleared)

	listed, err = h.admin.ListTiers(ctx, &pb.ListTiersRequest{})
	require.NoError(t, err)
	assert.Empty(t, listed.Tiers)

	// Clearing again still succeeds.
	cleared, err = h.admin.ClearTier(ctx, &pb.ClearTierRequest{Identity: identity})
	require.NoError(t, err)
	assert.True(t, cleared.Cleared)
}

// TestGRPCAdmin_SetTierValidation covers the TTL resolution order and the
// rejected inputs.
func TestGRPCAdmin_SetTierValidation(t *testing.T) {
	h := newAdminGRPCHarness(t, nil)
	ctx := adminCtx()

	t.Run("unknown tier", func(t *testing.T) {
		_, err := h.admin.SetTier(ctx, &pb.SetTierRequest{Identity: "x", Tier: "banana"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing identity", func(t *testing.T) {
		_, err := h.admin.SetTier(ctx, &pb.SetTierRequest{Tier: "watch"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("omitted ttl uses the configured tier ttl", func(t *testing.T) {
		resp, err := h.admin.SetTier(ctx, &pb.SetTierRequest{Identity: "ttl-default", Tier: "throttle"})
		require.NoError(t, err)
		assert.InDelta(t, time.Now().Add(15*time.Minute).Unix(), resp.UntilUnix, 60)
	})

	t.Run("ttl is capped by max_ttl", func(t *testing.T) {
		resp, err := h.admin.SetTier(ctx, &pb.SetTierRequest{Identity: "ttl-capped", Tier: "block", TtlSeconds: int64((72 * time.Hour).Seconds())})
		require.NoError(t, err)
		assert.InDelta(t, time.Now().Add(24*time.Hour).Unix(), resp.UntilUnix, 60)
	})
}

func TestGRPCAdmin_ListDecisions(t *testing.T) {
	h := newAdminGRPCHarness(t, nil)
	ctx := adminCtx()

	h.audit.Add(controller.DecisionRecord{ID: "d1", At: time.Unix(100, 0), Identity: "alpha", Label: judge.LabelScraper})
	h.audit.Add(controller.DecisionRecord{ID: "d2", At: time.Unix(200, 0), Identity: "beta", Label: judge.LabelL7Flood})
	h.audit.Add(controller.DecisionRecord{ID: "d3", At: time.Unix(300, 0), Identity: "alpha", Label: judge.LabelScraper})

	t.Run("newest first with filters", func(t *testing.T) {
		resp, err := h.admin.ListDecisions(ctx, &pb.ListDecisionsRequest{Identity: "alpha"})
		require.NoError(t, err)
		require.Len(t, resp.Decisions, 2)
		assert.Equal(t, "d3", resp.Decisions[0].Id)
		assert.Equal(t, "alpha", resp.Decisions[0].Identity)
		assert.Equal(t, "scraper", resp.Decisions[0].Label)
	})

	t.Run("label filter", func(t *testing.T) {
		resp, err := h.admin.ListDecisions(ctx, &pb.ListDecisionsRequest{Label: "l7_flood"})
		require.NoError(t, err)
		require.Len(t, resp.Decisions, 1)
		assert.Equal(t, "d2", resp.Decisions[0].Id)
	})

	t.Run("limit", func(t *testing.T) {
		resp, err := h.admin.ListDecisions(ctx, &pb.ListDecisionsRequest{Limit: 1})
		require.NoError(t, err)
		require.Len(t, resp.Decisions, 1)
		assert.Equal(t, "d3", resp.Decisions[0].Id)
	})

	t.Run("default limit", func(t *testing.T) {
		resp, err := h.admin.ListDecisions(ctx, &pb.ListDecisionsRequest{})
		require.NoError(t, err)
		assert.Len(t, resp.Decisions, 3)
	})
}

// TestGRPCAdmin_MissingDependencies verifies the AdminService degrades to
// Unavailable rather than panicking when a dependency was never wired.
func TestGRPCAdmin_MissingDependencies(t *testing.T) {
	h := newAdminGRPCHarness(t, func(cfg *GRPCConfig) {
		cfg.Tiers = nil
		cfg.Audit = nil
	})
	ctx := adminCtx()

	_, err := h.admin.SetTier(ctx, &pb.SetTierRequest{Identity: "x", Tier: "watch"})
	assert.Equal(t, codes.Unavailable, status.Code(err))

	_, err = h.admin.ClearTier(ctx, &pb.ClearTierRequest{Identity: "x"})
	assert.Equal(t, codes.Unavailable, status.Code(err))

	_, err = h.admin.ListTiers(ctx, &pb.ListTiersRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))

	_, err = h.admin.ListDecisions(ctx, &pb.ListDecisionsRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// TestGRPCReport verifies the public report RPC is reachable without a token
// and feeds the signals pipeline.
func TestGRPCReport(t *testing.T) {
	h := newAdminGRPCHarness(t, nil)

	t.Run("accepted without a token", func(t *testing.T) {
		resp, err := h.limiter.Report(context.Background(), &pb.ReportRequest{
			Identifier: "api-key-7",
			Resource:   "/v1/items",
			Status:     201,
			Path:       "/v1/items",
			Method:     "POST",
			UserAgent:  "curl/8.4.0",
		})
		require.NoError(t, err)
		assert.True(t, resp.Accepted)

		obs := h.signals.observations()
		require.Len(t, obs, 1)
		assert.Equal(t, "api-key-7", obs[0].Identity)
		assert.Equal(t, "/v1/items", obs[0].Route)
		assert.Equal(t, 201, obs[0].Status)
		assert.True(t, obs[0].Allowed)
	})

	t.Run("missing identifier is rejected", func(t *testing.T) {
		_, err := h.limiter.Report(context.Background(), &pb.ReportRequest{Resource: "x"})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}

// TestGRPC_CheckAttributes verifies the optional attributes on CheckRateLimit
// reach the signals pipeline and never affect the decision.
func TestGRPC_CheckAttributes(t *testing.T) {
	h := newAdminGRPCHarness(t, nil)
	ctx := context.Background()

	resp, err := h.limiter.CheckRateLimit(ctx, &pb.CheckRequest{
		Identifier: "attrs-user",
		Resource:   "/v1/items",
		Tokens:     1,
		Attributes: &pb.Attributes{Path: "/v1/items/42", Method: "GET", UserAgent: "Go-http-client/2.0"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Allowed)

	obs := h.signals.observations()
	require.Len(t, obs, 1)
	assert.Equal(t, "attrs-user", obs[0].Identity)
	assert.Equal(t, "/v1/items", obs[0].Route)
	assert.Equal(t, "/v1/items/42", obs[0].Path)
	assert.Equal(t, "GET", obs[0].Method)
	assert.True(t, obs[0].Allowed)

	t.Run("absent attributes record nothing", func(t *testing.T) {
		_, err := h.limiter.CheckRateLimit(ctx, &pb.CheckRequest{Identifier: "no-attrs", Tokens: 1})
		require.NoError(t, err)
		assert.Len(t, h.signals.observations(), 1)
	})
}
