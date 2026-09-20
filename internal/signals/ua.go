package signals

import "strings"

// authRouteMarkers are the substrings that mark a route as authentication-ish.
// Auth-failure ratios are only meaningful against routes like these.
var authRouteMarkers = []string{"login", "signin", "sign-in", "auth", "token", "session", "oauth", "password"}

// IsAuthRoute reports whether a route template looks like an authentication
// endpoint.
func IsAuthRoute(route string) bool {
	lower := strings.ToLower(route)
	for _, marker := range authRouteMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// ClassifyUA maps a User-Agent header to a coarse client family.
//
// The order of the checks matters: a declared crawler and a headless browser
// both carry browser-like strings, so they are recognized first.
func ClassifyUA(ua string) UAFamily {
	trimmed := strings.TrimSpace(ua)
	if trimmed == "" {
		return UAEmpty
	}
	lower := strings.ToLower(trimmed)

	// Declared crawlers and monitoring agents.
	for _, marker := range []string{
		"bot", "crawler", "crawl", "spider", "slurp", "bingpreview", "facebookexternalhit",
		"monitoring", "uptime", "pingdom", "statuscake", "nagios", "zabbix", "googlebot",
		"semrush", "ahrefs", "datadog", "newrelic", "site24x7", "healthcheck",
	} {
		if strings.Contains(lower, marker) {
			return UABotDeclared
		}
	}

	// Automation frameworks that drive a real browser.
	for _, marker := range []string{
		"headlesschrome", "headless", "phantomjs", "puppeteer", "playwright",
		"selenium", "webdriver", "electron/",
	} {
		if strings.Contains(lower, marker) {
			return UAHeadless
		}
	}

	// Command-line clients.
	if strings.Contains(lower, "curl/") || strings.Contains(lower, "wget/") || strings.Contains(lower, "httpie/") {
		return UACurl
	}

	// Language runtimes.
	if strings.Contains(lower, "python-requests") || strings.Contains(lower, "python-urllib") ||
		strings.Contains(lower, "aiohttp") || strings.Contains(lower, "httpx/") || strings.Contains(lower, "python/") {
		return UAPython
	}
	if strings.Contains(lower, "go-http-client") || strings.Contains(lower, "golang") {
		return UAGo
	}
	if strings.Contains(lower, "java/") || strings.Contains(lower, "okhttp") || strings.Contains(lower, "apache-httpclient") ||
		strings.Contains(lower, "libwww-perl") {
		return UAJava
	}

	// Real browsers.
	if strings.Contains(lower, "mozilla/") &&
		(strings.Contains(lower, "chrome") || strings.Contains(lower, "safari") ||
			strings.Contains(lower, "firefox") || strings.Contains(lower, "edg") ||
			strings.Contains(lower, "gecko")) {
		return UABrowser
	}

	return UAOther
}
