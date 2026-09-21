package netx

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	p, err := ParsePrefixes(cidrs)
	require.NoError(t, err)
	return p
}

func addr(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a
}

func TestClientIP(t *testing.T) {
	trusted := mustPrefixes(t, "10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32")

	tests := []struct {
		name       string
		remoteAddr string
		xff        []string
		trusted    []netip.Prefix
		want       string
	}{
		{
			name:       "no xff, untrusted peer",
			remoteAddr: "203.0.113.7:5555",
			want:       "203.0.113.7",
		},
		{
			name:       "xff ignored from untrusted peer",
			remoteAddr: "203.0.113.7:5555",
			xff:        []string{"1.2.3.4"},
			trusted:    trusted,
			want:       "203.0.113.7",
		},
		{
			name:       "trusted peer without xff",
			remoteAddr: "10.0.0.5:80",
			trusted:    trusted,
			want:       "10.0.0.5",
		},
		{
			name:       "spoofed xff from untrusted peer is ignored",
			remoteAddr: "198.51.100.9",
			xff:        []string{"127.0.0.1, 10.0.0.1"},
			trusted:    trusted,
			want:       "198.51.100.9",
		},
		{
			name:       "trusted chain of three resolves the original client",
			remoteAddr: "10.0.0.1:443",
			xff:        []string{"203.0.113.50, 10.0.0.2, 10.0.0.3"},
			trusted:    trusted,
			want:       "203.0.113.50",
		},
		{
			name:       "all hops trusted falls back to the leftmost",
			remoteAddr: "10.0.0.1:443",
			xff:        []string{"10.0.0.9, 10.0.0.8"},
			trusted:    trusted,
			want:       "10.0.0.9",
		},
		{
			name:       "first untrusted hop from the right wins",
			remoteAddr: "10.0.0.1:443",
			xff:        []string{"203.0.113.50, 198.51.100.4, 10.0.0.3"},
			trusted:    trusted,
			want:       "198.51.100.4",
		},
		{
			name:       "spaces are trimmed",
			remoteAddr: "10.0.0.1:443",
			xff:        []string{"  203.0.113.50 ,  10.0.0.3  "},
			trusted:    trusted,
			want:       "203.0.113.50",
		},
		{
			name:       "multiple xff headers are concatenated in order",
			remoteAddr: "10.0.0.1:443",
			xff:        []string{"203.0.113.50", "10.0.0.3"},
			trusted:    trusted,
			want:       "203.0.113.50",
		},
		{
			name:       "empty header entries are skipped",
			remoteAddr: "10.0.0.1:443",
			xff:        []string{"203.0.113.50,,", "  "},
			trusted:    trusted,
			want:       "203.0.113.50",
		},
		{
			name:       "invalid hop falls back to the peer",
			remoteAddr: "10.0.0.1:443",
			xff:        []string{"203.0.113.50, not-an-ip"},
			trusted:    trusted,
			want:       "10.0.0.1",
		},
		{
			name:       "ipv6 with zone",
			remoteAddr: "[fe80::1%eth0]:443",
			want:       "fe80::1",
		},
		{
			name:       "ipv4 mapped ipv6 is unmapped",
			remoteAddr: "[::ffff:192.0.2.10]:443",
			want:       "192.0.2.10",
		},
		{
			name:       "xff entry carrying a port",
			remoteAddr: "10.0.0.1:443",
			xff:        []string{"203.0.113.50:1234, 10.0.0.3"},
			trusted:    trusted,
			want:       "203.0.113.50",
		},
		{
			name:       "bracketed ipv6 xff entry",
			remoteAddr: "10.0.0.1:443",
			xff:        []string{"[2001:db8::5]:1234, 10.0.0.3"},
			trusted:    trusted,
			want:       "2001:db8::5",
		},
		{
			name:       "trusted peer without port",
			remoteAddr: "10.0.0.5",
			trusted:    trusted,
			want:       "10.0.0.5",
		},
		{
			name:       "empty remote addr yields invalid address",
			remoteAddr: "",
			trusted:    trusted,
			want:       "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClientIP(tt.remoteAddr, tt.xff, tt.trusted)
			if tt.want == "invalid" {
				assert.False(t, got.IsValid())
				return
			}
			assert.Equal(t, tt.want, got.String())
		})
	}
}

func TestTrusted(t *testing.T) {
	trusted := mustPrefixes(t, "10.0.0.0/8")

	assert.True(t, Trusted(addr("10.1.2.3"), trusted))
	assert.False(t, Trusted(addr("11.1.2.3"), trusted))
	assert.False(t, Trusted(netip.Addr{}, trusted))
	assert.False(t, Trusted(addr("10.1.2.3"), nil))
}

func TestParsePrefixes(t *testing.T) {
	t.Run("cidr and bare address", func(t *testing.T) {
		got, err := ParsePrefixes([]string{"10.0.0.0/8", "192.0.2.1", " 2001:db8::/32 "})
		require.NoError(t, err)
		require.Len(t, got, 3)
		assert.Equal(t, "10.0.0.0/8", got[0].String())
		assert.Equal(t, "192.0.2.1/32", got[1].String())
		assert.Equal(t, "2001:db8::/32", got[2].String())
	})

	t.Run("masked", func(t *testing.T) {
		got, err := ParsePrefixes([]string{"10.1.2.3/8"})
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.0/8", got[0].String())
	})

	t.Run("empty list", func(t *testing.T) {
		got, err := ParsePrefixes(nil)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("invalid entries", func(t *testing.T) {
		_, err := ParsePrefixes([]string{"not-a-cidr"})
		assert.Error(t, err)
		_, err = ParsePrefixes([]string{"10.0.0.0/99"})
		assert.Error(t, err)
	})
}

func TestPrefixOf(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"203.0.113.57", "203.0.113.0/24"},
		{"::ffff:203.0.113.57", "203.0.113.0/24"},
		{"2001:db8:1234:5678:9abc::1", "2001:db8:1234::/48"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, PrefixOf(addr(tt.in)).String())
		})
	}

	t.Run("invalid address", func(t *testing.T) {
		assert.False(t, PrefixOf(netip.Addr{}).IsValid())
	})
}

func TestIdentity(t *testing.T) {
	ip := addr("203.0.113.5")

	tests := []struct {
		name     string
		explicit string
		apiKey   string
		want     string
	}{
		{"explicit wins", "user-1", "key-1", "user-1"},
		{"api key second", "", "key-1", "key-1"},
		{"ip last", "", "", "203.0.113.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Identity(tt.explicit, tt.apiKey, ip))
		})
	}

	t.Run("invalid ip with no credentials", func(t *testing.T) {
		assert.Equal(t, "unknown", Identity("", "", netip.Addr{}))
	})
}

func FuzzClientIP(f *testing.F) {
	seeds := []struct {
		remote string
		xff    string
	}{
		{"203.0.113.7:5555", ""},
		{"10.0.0.1:443", "203.0.113.50, 10.0.0.3"},
		{"[::1]:443", "::1, ::ffff:1.2.3.4"},
		{"", "garbage"},
	}
	for _, s := range seeds {
		f.Add(s.remote, s.xff)
	}

	trusted, err := ParsePrefixes([]string{"10.0.0.0/8", "2001:db8::/32"})
	if err != nil {
		f.Fatalf("ParsePrefixes: %v", err)
	}

	f.Fuzz(func(t *testing.T, remote, xff string) {
		got := ClientIP(remote, []string{xff}, trusted)

		peer, peerOK := ParseAddr(remote)
		if peerOK && !Trusted(peer, trusted) {
			assert.Equal(t, peer, got)
			return
		}

		// The result is either the peer or one of the supplied hops. Anything
		// else would mean we manufactured an address out of thin air.
		if !got.IsValid() {
			return
		}
		if peerOK && got == peer {
			return
		}
		for _, hop := range parseChain([]string{xff}) {
			if got == hop {
				return
			}
		}
		t.Fatalf("ClientIP(%q, %q) = %s, which is neither the peer nor an XFF hop", remote, xff, got)
	})
}
