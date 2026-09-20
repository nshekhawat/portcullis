package signals

import "strings"

// MaxPathLength bounds the raw path kept in an observation. Paths are
// client-supplied and are only used for sampling, so they are truncated rather
// than trusted.
const MaxPathLength = 128

// SanitizePath normalises a raw request path for sampling: control characters
// and whitespace runs become single spaces, and the result is truncated to
// MaxPathLength bytes on a rune boundary.
//
// The output is still untrusted text. It is sent to a judge only as data, with
// the prompt saying so explicitly.
func SanitizePath(path string) string {
	if path == "" {
		return ""
	}

	// Strip a query string: it carries secrets and adds no classification value.
	if idx := strings.IndexAny(path, "?#"); idx >= 0 {
		path = path[:idx]
	}

	var b strings.Builder
	b.Grow(len(path))
	lastSpace := false
	for _, r := range path {
		switch {
		case r < 0x20 || r == 0x7f:
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
		case r == ' ':
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
		default:
			b.WriteRune(r)
			lastSpace = false
		}
	}

	out := strings.TrimSpace(b.String())
	return truncateBytes(out, MaxPathLength)
}

// truncateBytes cuts s to at most n bytes without splitting a UTF-8 rune.
func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// isRuneStart reports whether b can begin a UTF-8 sequence.
func isRuneStart(b byte) bool {
	return b&0xc0 != 0x80
}
