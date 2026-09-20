package demoupstream

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler_Routes(t *testing.T) {
	server := httptest.NewServer(Handler())
	defer server.Close()

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
	}{
		{"root", http.MethodGet, "/", "", http.StatusOK},
		{"health", http.MethodGet, "/healthz", "", http.StatusOK},
		{"product in range", http.MethodGet, "/products/42", "", http.StatusOK},
		{"product at the boundary", http.MethodGet, "/products/1000", "", http.StatusOK},
		{"product above the range", http.MethodGet, "/products/1001", "", http.StatusNotFound},
		{"product not a number", http.MethodGet, "/products/abc", "", http.StatusNotFound},
		{"order in range", http.MethodGet, "/api/orders/7", "", http.StatusOK},
		{"order above the range", http.MethodGet, "/api/orders/9999", "", http.StatusNotFound},
		{"login with demo credentials", http.MethodPost, "/login", LoginBody(DemoUser, DemoPassword), http.StatusOK},
		{"login with bad credentials", http.MethodPost, "/login", LoginBody("demo", "wrong"), http.StatusUnauthorized},
		{"login with an empty body", http.MethodPost, "/login", "", http.StatusBadRequest},
		{"flaky always fails", http.MethodGet, "/flaky", "", http.StatusServiceUnavailable},
		{"unknown path", http.MethodGet, "/nope", "", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, server.URL+tt.path, bodyReader(tt.body))
			require.NoError(t, err)
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}

			resp, err := server.Client().Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tt.wantStatus, resp.StatusCode)
		})
	}
}

// TestSensitivePaths_AllMissing checks that the scanner scenario's probes really
// do 404, so its 404-driven classification is honest.
func TestSensitivePaths_AllMissing(t *testing.T) {
	server := httptest.NewServer(Handler())
	defer server.Close()

	paths := SensitivePaths()
	require.NotEmpty(t, paths)

	for _, path := range paths {
		resp, err := server.Client().Get(server.URL + path)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "path %s should be missing", path)
	}
}

func TestIsAuthPath(t *testing.T) {
	assert.True(t, IsAuthPath("/login"))
	assert.True(t, IsAuthPath("/login/step2"))
	assert.False(t, IsAuthPath("/products/1"))
}

// bodyReader returns a reader for an optional body.
func bodyReader(body string) io.Reader {
	return strings.NewReader(body)
}
