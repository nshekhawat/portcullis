package detect

import (
	"net/netip"
	"strings"

	"github.com/nshekhawat/portcullis/internal/netx"
	"github.com/nshekhawat/portcullis/internal/signals"
)

// Hard evidence is the only thing that can unlock a block (guardrail G3), so
// every rule here is deterministic and cheap to explain: no statistics, no
// thresholds learned at runtime.

// campaignMinPeers is how many suspects must share an aggregate prefix before
// the group counts as a coordinated campaign.
const campaignMinPeers = 5

// builtinScannerPaths are the path markers that count as probing for sensitive
// files, admin panels and framework internals. Every marker is rooted at "/",
// so a match always lands on a path boundary.
var builtinScannerPaths = []string{
	"/.env",
	"/.git/",
	"/wp-login.php",
	"/wp-admin",
	"/phpmyadmin",
	"/server-status",
	"/actuator",
	"/.aws/",
	"/config.json",
	"/vendor/phpunit",
	"/cgi-bin/",
}

// ScannerPaths returns a copy of the built-in sensitive-path markers. Callers
// may override them through HardEvidenceOptions.ScannerPaths.
func ScannerPaths() []string {
	out := make([]string, len(builtinScannerPaths))
	copy(out, builtinScannerPaths)
	return out
}

// scannerPathMatch reports whether any sampled path carries one of the markers.
// Matching is case-insensitive and substring-based, which for the built-in list
// means a path-segment match; empty markers never match.
func scannerPathMatch(paths, markers []string) bool {
	for _, path := range paths {
		if path == "" {
			continue
		}

		lower := strings.ToLower(path)
		for _, marker := range markers {
			if marker == "" {
				continue
			}
			if strings.Contains(lower, strings.ToLower(marker)) {
				return true
			}
		}
	}
	return false
}

// campaignMembers returns the identities that share an aggregate prefix — a /24
// for IPv4, a /48 for IPv6 — with at least campaignMinPeers of the other
// suspects.
//
// Identities that are not addresses cannot join a campaign: an API key has no
// address to aggregate, and a prefix window is already an aggregate of its own.
func campaignMembers(identities []string) map[string]struct{} {
	groups := make(map[netip.Prefix][]string, len(identities))
	for _, identity := range identities {
		addr, ok := netx.ParseAddr(identity)
		if !ok {
			continue
		}
		prefix := netx.PrefixOf(addr)
		groups[prefix] = append(groups[prefix], identity)
	}

	members := make(map[string]struct{})
	for _, group := range groups {
		if len(group) < campaignMinPeers {
			continue
		}
		for _, identity := range group {
			members[identity] = struct{}{}
		}
	}
	return members
}

// evidenceFlags assembles the hard-evidence flags for one window, always in the
// same order so the output is stable. campaign reports whether the identity
// belongs to a prefix campaign.
//
// opts must already carry its defaults; a zero MinAuthAttempts would let the
// auth rule fire without any attempts behind it.
func evidenceFlags(w *signals.IdentityWindow, opts HardEvidenceOptions, campaign bool) []string {
	var flags []string

	if w.RPS() >= opts.RPSCeiling {
		flags = append(flags, EvidenceRateOverHardCeiling)
	}
	if w.AuthAttempts >= int64(opts.MinAuthAttempts) && w.AuthFailRatio() >= opts.AuthFailRatio {
		flags = append(flags, EvidenceAuthFailRatioHigh)
	}

	markers := opts.ScannerPaths
	if len(markers) == 0 {
		markers = builtinScannerPaths
	}
	if scannerPathMatch(w.SampledPaths, markers) {
		flags = append(flags, EvidenceScannerPaths)
	}
	if campaign {
		flags = append(flags, EvidencePrefixCampaign)
	}

	return flags
}
