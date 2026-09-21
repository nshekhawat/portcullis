package signals

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUAFamily(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want UAFamily
	}{
		{name: "empty", ua: "", want: UAEmpty},
		{name: "whitespace only", ua: "   ", want: UAEmpty},
		{name: "curl", ua: "curl/8.4.0", want: UACurl},
		{name: "wget", ua: "Wget/1.21.4 (linux-gnu)", want: UACurl},
		{name: "python requests", ua: "python-requests/2.31.0", want: UAPython},
		{name: "go http client", ua: "Go-http-client/2.0", want: UAGo},
		{name: "okhttp", ua: "okhttp/4.12.0", want: UAJava},
		{
			name: "headless chrome",
			ua:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
			want: UAHeadless,
		},
		{
			name: "declared crawler",
			ua:   "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			want: UABotDeclared,
		},
		{
			name: "real chrome",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
			want: UABrowser,
		},
		{name: "unknown client", ua: "Zanarkand/1.0", want: UAOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ClassifyUA(tt.ua))
		})
	}
}

func TestUAFamilyString(t *testing.T) {
	tests := []struct {
		family UAFamily
		want   string
	}{
		{UAEmpty, "empty"},
		{UABrowser, "browser"},
		{UACurl, "curl"},
		{UAPython, "python"},
		{UAGo, "go"},
		{UAJava, "java"},
		{UAHeadless, "headless"},
		{UABotDeclared, "bot_declared"},
		{UAOther, "other"},
		{UAFamily(200), "other"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.family.String())
		})
	}
}
