package signals

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestPathTruncation(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty stays empty", in: "", want: ""},
		{name: "a clean path is untouched", in: "/v1/items/42", want: "/v1/items/42"},
		{name: "the query string is dropped", in: "/search?q=secret&token=x", want: "/search"},
		{name: "the fragment is dropped", in: "/page#section", want: "/page"},
		{name: "control characters become single spaces", in: "/a\x00b\nc\td\x7f", want: "/a b c d"},
		{name: "whitespace runs collapse", in: "/a\t\t\n b", want: "/a b"},
		{
			name: "an over-long path is cut to the byte budget",
			in:   "/" + strings.Repeat("a", 300),
			want: "/" + strings.Repeat("a", MaxPathLength-1),
		},
		{
			// The byte budget lands inside a multi-byte rune, so the cut has to
			// walk back to the rune boundary: 127 bytes, not 128.
			name: "a cut never splits a rune",
			in:   "/" + strings.Repeat("é", 100),
			want: "/" + strings.Repeat("é", 63),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizePath(tt.in)

			assert.Equal(t, tt.want, got)
			assert.LessOrEqual(t, len(got), MaxPathLength)
			assert.True(t, utf8.ValidString(got), "output must stay valid UTF-8: %q", got)
			assert.NotContains(t, got, "?", "query strings never reach a sample")
		})
	}
}

func FuzzSanitizePath(f *testing.F) {
	for _, seed := range []string{
		"",
		"/",
		"/v1/items/42",
		"/search?q=secret&token=x#fragment",
		"/a\x00b\nc\td\x7f",
		"/wp-login.php",
		"/" + strings.Repeat("a", 400),
		"/" + strings.Repeat("é", 200),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, path string) {
		out := SanitizePath(path)

		assert.LessOrEqual(t, len(out), MaxPathLength)
		assert.NotContains(t, out, "?")
		assert.NotContains(t, out, "#")
		assert.NotContains(t, out, "  ", "whitespace runs are collapsed")
		assert.False(t, strings.HasPrefix(out, " "), "leading whitespace is trimmed")

		for _, r := range out {
			assert.False(t, r < 0x20 || r == 0x7f, "control character %q survived in %q", r, out)
		}
	})
}
