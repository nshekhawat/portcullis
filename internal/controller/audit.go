package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/policy"
)

// Mode selects how much of the judgment plane is allowed to act.
type Mode string

// Judgment modes.
const (
	// ModeOff disables the controller entirely.
	ModeOff Mode = "off"
	// ModeShadow computes and audits decisions but never writes a tier.
	ModeShadow Mode = "shadow"
	// ModeEnforce applies guardrail-approved tier changes.
	ModeEnforce Mode = "enforce"
)

// DecisionRecord is the audit entry for one judged suspect.
type DecisionRecord struct {
	ID         string                  `json:"id"`
	At         time.Time               `json:"at"`
	Identity   string                  `json:"identity"`
	SuspectID  string                  `json:"suspect_id"`
	Score      float64                 `json:"score"`
	Evidence   []string                `json:"evidence,omitempty"`
	Features   detect.SemanticFeatures `json:"features"`
	Judge      string                  `json:"judge"`
	Model      string                  `json:"model,omitempty"`
	Label      judge.Label             `json:"label"`
	Confidence float64                 `json:"confidence"`
	Proposed   policy.Tier             `json:"proposed_tier"`
	Applied    policy.Tier             `json:"applied_tier"`
	Previous   policy.Tier             `json:"previous_tier"`
	Guardrails []string                `json:"guardrails_applied,omitempty"`
	Reason     string                  `json:"reason,omitempty"`
	Mode       Mode                    `json:"mode"`
	LatencyMS  float64                 `json:"latency_ms"`
}

// Filter narrows an audit query.
type Filter struct {
	Limit    int
	Identity string
	Label    judge.Label
}

// AuditRing is a fixed-size ring of decision records, newest first.
type AuditRing struct {
	mu    sync.RWMutex
	buf   []DecisionRecord
	next  int
	full  bool
	limit int
}

// NewAuditRing returns a ring holding at most size records.
func NewAuditRing(size int) *AuditRing {
	if size < 1 {
		size = 1
	}
	return &AuditRing{buf: make([]DecisionRecord, size)}
}

// Add records a decision, overwriting the oldest when full.
//
//nolint:gocritic // the ring owns its copies; a pointer would alias the caller
func (r *AuditRing) Add(rec DecisionRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.buf[r.next] = rec
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
	r.limit++
}

// Len reports how many records the ring holds.
func (r *AuditRing) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.full {
		return len(r.buf)
	}
	return r.next
}

// List returns records newest first, filtered and limited.
func (r *AuditRing) List(f Filter) []DecisionRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]DecisionRecord, 0, r.Len())
	for i := 0; i < r.Len(); i++ {
		// Walk backwards from the most recently written slot.
		idx := (r.next - 1 - i + len(r.buf)*2) % len(r.buf)
		rec := r.buf[idx]
		if f.Identity != "" && rec.Identity != f.Identity {
			continue
		}
		if f.Label != "" && rec.Label != f.Label {
			continue
		}
		out = append(out, rec)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out
}

// hashPrefix returns the first 12 hex characters of the SHA-256 of s.
func hashPrefix(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}
