// Package netx resolves the originating client address behind proxies and
// derives rate-limit identities and aggregates from it.
//
// The rules exist because X-Forwarded-For is attacker-controlled: a client can
// send any value it likes. Only hops contributed by proxies we explicitly trust
// may be believed (B2).
package netx

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ClientIP returns the originating client address.
//
// If the direct peer (remoteAddr) is not a trusted proxy, X-Forwarded-For is
// ignored entirely and the peer is returned. Otherwise the headers are walked
// right-to-left, skipping trusted hops; the first untrusted hop is the client.
// An unparsable hop aborts the walk and the peer is returned, since a broken
// chain cannot be attributed. IPv4-mapped IPv6 addresses are unmapped.
//
// xff holds the raw X-Forwarded-For header values in the order they arrived;
// each value may itself contain a comma-separated list.
func ClientIP(remoteAddr string, xff []string, trusted []netip.Prefix) netip.Addr {
	peer, ok := ParseAddr(remoteAddr)
	if !ok {
		return netip.Addr{}
	}

	if !Trusted(peer, trusted) {
		return peer
	}

	hops := parseChain(xff)

	// Walk right-to-left: the rightmost hops were appended by the proxies we
	// trust, so the first untrusted hop is the real client.
	for i := len(hops) - 1; i >= 0; i-- {
		if Trusted(hops[i], trusted) {
			continue
		}
		return hops[i]
	}

	// Every hop was trusted: the client is the leftmost one.
	if len(hops) > 0 {
		return hops[0]
	}
	return peer
}

// parseChain flattens X-Forwarded-For values into addresses, left to right.
//
// Empty entries are dropped. An unparsable entry invalidates everything to its
// left, because we can no longer attribute those hops to anyone; only the hops
// to its right are returned. A chain ending in garbage therefore yields no hops
// at all and ClientIP falls back to the peer.
func parseChain(xff []string) []netip.Addr {
	type entry struct {
		addr netip.Addr
		ok   bool
	}

	var entries []entry
	for _, header := range xff {
		for _, part := range strings.Split(header, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			addr, ok := parseHop(part)
			entries = append(entries, entry{addr: addr, ok: ok})
		}
	}

	lastInvalid := -1
	for i, e := range entries {
		if !e.ok {
			lastInvalid = i
		}
	}

	hops := make([]netip.Addr, 0, len(entries)-lastInvalid-1)
	for _, e := range entries[lastInvalid+1:] {
		hops = append(hops, e.addr)
	}
	return hops
}

// parseHop parses a single X-Forwarded-For entry. Entries may carry a port
// ("1.2.3.4:80"), a bracketed IPv6 port ("[::1]:80") or a zone ("fe80::1%eth0").
func parseHop(s string) (netip.Addr, bool) {
	if strings.HasPrefix(s, "[") {
		if host, _, err := net.SplitHostPort(s); err == nil {
			s = host
		} else {
			s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
		}
	} else if strings.Count(s, ":") == 1 {
		if host, _, err := net.SplitHostPort(s); err == nil {
			s = host
		}
	}

	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	return addr.Unmap(), true
}

// ParseAddr parses "host", "host:port" or "[v6]:port" into an address with any
// IPv4-mapped form unmapped. An empty or unparsable input returns false.
func ParseAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, false
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	return addr.Unmap(), true
}

// Trusted reports whether addr falls inside any trusted prefix.
func Trusted(addr netip.Addr, trusted []netip.Prefix) bool {
	if !addr.IsValid() {
		return false
	}
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ParsePrefixes parses a list of CIDR strings. A bare address is accepted and
// treated as a single-host prefix. An empty list yields no prefixes.
func ParsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
			}
			prefixes = append(prefixes, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", raw, err)
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

// PrefixOf returns the aggregate prefix an address belongs to: /24 for IPv4 and
// /48 for IPv6. It is used for campaign detection and tier entries.
func PrefixOf(ip netip.Addr) netip.Prefix {
	if !ip.IsValid() {
		return netip.Prefix{}
	}
	ip = ip.Unmap()
	bits := 24
	if ip.Is6() {
		bits = 48
	}
	return netip.PrefixFrom(ip, bits).Masked()
}

// Identity derives the rate-limit identity, preferring an explicit identifier,
// then an API key, then the client address.
func Identity(explicitID, apiKey string, ip netip.Addr) string {
	if explicitID != "" {
		return explicitID
	}
	if apiKey != "" {
		return apiKey
	}
	if ip.IsValid() {
		return ip.String()
	}
	return "unknown"
}
