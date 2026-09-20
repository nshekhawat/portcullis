// Package mock provides scripted judge.Judge implementations for tests.
//
// A mock returns exactly what the test asks for, so the controller and the
// audit path can be exercised without a model in the loop.
package mock

import (
	"context"

	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
)

// Name identifies this judge in audit records and metrics.
const Name = "mock"

// Judge is a scripted judge.Judge. It holds no per-call state: the script is
// replayed from the start on every call, so repeated calls return identical
// verdicts.
type Judge struct {
	script     []judge.Verdict
	err        error
	label      judge.Label
	confidence float64
	defaulted  bool
}

// New returns a mock judge that replays script. A scripted verdict with a
// non-empty SuspectID is returned for that suspect wherever it appears in the
// batch; verdicts without one are handed out positionally, in script order.
func New(script ...judge.Verdict) *Judge {
	return &Judge{script: script}
}

// NewWithError returns a mock judge whose Judge method always fails with err.
func NewWithError(err error) *Judge {
	return &Judge{err: err}
}

// NewWithLabel returns a mock judge that answers every suspect with label at
// confidence.
func NewWithLabel(label judge.Label, confidence float64) *Judge {
	return &Judge{label: label, confidence: confidence, defaulted: true}
}

// Name returns "mock".
func (j *Judge) Name() string { return Name }

// Judge returns the scripted verdicts. Suspects that the script does not
// cover are skipped unless the judge was built with NewWithLabel, so a short
// script yields partial results rather than an error.
func (j *Judge) Judge(ctx context.Context, suspects []detect.Suspect) ([]judge.Verdict, error) {
	if j.err != nil {
		return nil, j.err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	byID := make(map[string]judge.Verdict, len(j.script))
	positional := make([]judge.Verdict, 0, len(j.script))
	for i := range j.script {
		v := j.script[i]
		if v.SuspectID != "" {
			byID[v.SuspectID] = v
			continue
		}
		positional = append(positional, v)
	}
	verdicts := make([]judge.Verdict, 0, len(suspects))
	next := 0
	for i := range suspects {
		s := &suspects[i]
		if v, ok := byID[s.SuspectID]; ok {
			verdicts = append(verdicts, stamp(v, s.SuspectID))
			continue
		}
		if next < len(positional) {
			verdicts = append(verdicts, stamp(positional[next], s.SuspectID))
			next++
			continue
		}
		if j.defaulted {
			verdicts = append(verdicts, judge.Verdict{
				SuspectID:  s.SuspectID,
				Label:      j.label,
				Confidence: j.confidence,
				Judge:      Name,
			})
		}
	}
	return verdicts, nil
}

// stamp fills in the identity fields a script may have left blank.
//
//nolint:gocritic // Verdict is returned by value by design
func stamp(v judge.Verdict, suspectID string) judge.Verdict {
	if v.SuspectID == "" {
		v.SuspectID = suspectID
	}
	if v.Judge == "" {
		v.Judge = Name
	}
	return v
}

// Judge is a judge.Judge.
var _ judge.Judge = (*Judge)(nil)
