package mock

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
)

// batch builds a suspect batch with the given ids.
func batch(ids ...string) []detect.Suspect {
	suspects := make([]detect.Suspect, 0, len(ids))
	for _, id := range ids {
		suspects = append(suspects, detect.Suspect{SuspectID: id, Identity: "10.0.0.1"})
	}
	return suspects
}

// TestMock_Name checks the judge identity used in audit records.
func TestMock_Name(t *testing.T) {
	assert.Equal(t, "mock", New().Name())
}

// TestMock_Positional checks that a script without ids is handed out in order,
// and that the script is replayed identically on every call.
func TestMock_Positional(t *testing.T) {
	j := New(
		judge.Verdict{Label: judge.LabelScraper, Confidence: 0.7},
		judge.Verdict{Label: judge.LabelL7Flood, Confidence: 0.8},
	)
	suspects := batch("s00", "s01")

	want := []judge.Verdict{
		{SuspectID: "s00", Label: judge.LabelScraper, Confidence: 0.7, Judge: "mock"},
		{SuspectID: "s01", Label: judge.LabelL7Flood, Confidence: 0.8, Judge: "mock"},
	}
	got, err := j.Judge(context.Background(), suspects)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	again, err := j.Judge(context.Background(), suspects)
	require.NoError(t, err)
	assert.Equal(t, want, again)
}

// TestMock_ByID checks that a scripted verdict with an id is returned for that
// suspect regardless of position, and that a scripted judge name is preserved.
func TestMock_ByID(t *testing.T) {
	j := New(
		judge.Verdict{SuspectID: "s02", Label: judge.LabelVulnerabilityScanner, Confidence: 0.9, Judge: "custom"},
		judge.Verdict{SuspectID: "s00", Label: judge.LabelCredentialStuffing, Confidence: 0.85},
	)

	got, err := j.Judge(context.Background(), batch("s00", "s01", "s02"))
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, judge.Verdict{
		SuspectID:  "s00",
		Label:      judge.LabelCredentialStuffing,
		Confidence: 0.85,
		Judge:      "mock",
	}, got[0])
	assert.Equal(t, judge.Verdict{
		SuspectID:  "s02",
		Label:      judge.LabelVulnerabilityScanner,
		Confidence: 0.9,
		Judge:      "custom",
	}, got[1])
}

// TestMock_Mixed checks that id-matched and positional entries coexist: ids
// win, and positional entries are consumed by the remaining suspects in order.
func TestMock_Mixed(t *testing.T) {
	j := New(
		judge.Verdict{SuspectID: "s02", Label: judge.LabelVulnerabilityScanner, Confidence: 0.9},
		judge.Verdict{Label: judge.LabelLegitimateBurst, Confidence: 0.5},
		judge.Verdict{Label: judge.LabelScraper, Confidence: 0.75},
	)

	got, err := j.Judge(context.Background(), batch("s00", "s01", "s02"))
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "s00", got[0].SuspectID)
	assert.Equal(t, judge.LabelLegitimateBurst, got[0].Label)
	assert.Equal(t, "s01", got[1].SuspectID)
	assert.Equal(t, judge.LabelScraper, got[1].Label)
	assert.Equal(t, "s02", got[2].SuspectID)
	assert.Equal(t, judge.LabelVulnerabilityScanner, got[2].Label)
}

// TestMock_ShortScript checks partial results: uncovered suspects are skipped,
// not failed.
func TestMock_ShortScript(t *testing.T) {
	got, err := New(judge.Verdict{Label: judge.LabelScraper, Confidence: 0.75}).
		Judge(context.Background(), batch("s00", "s01", "s02"))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "s00", got[0].SuspectID)
}

// TestMock_EmptyScript checks the empty batch boundary.
func TestMock_EmptyScript(t *testing.T) {
	got, err := New().Judge(context.Background(), batch("s00"))
	require.NoError(t, err)
	assert.Empty(t, got)

	got, err = New().Judge(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestMock_DefaultLabel checks the fixed per-label mode.
func TestMock_DefaultLabel(t *testing.T) {
	j := NewWithLabel(judge.LabelMisbehavingClient, 0.75)

	got, err := j.Judge(context.Background(), batch("s00", "s01"))
	require.NoError(t, err)
	assert.Equal(t, []judge.Verdict{
		{SuspectID: "s00", Label: judge.LabelMisbehavingClient, Confidence: 0.75, Judge: "mock"},
		{SuspectID: "s01", Label: judge.LabelMisbehavingClient, Confidence: 0.75, Judge: "mock"},
	}, got)
}

// TestMock_Error checks the failure path.
func TestMock_Error(t *testing.T) {
	sentinel := errors.New("judge unavailable")
	j := NewWithError(sentinel)
	assert.Equal(t, "mock", j.Name())

	got, err := j.Judge(context.Background(), batch("s00"))
	assert.ErrorIs(t, err, sentinel)
	assert.Nil(t, got)
}

// TestMock_ContextCancelled checks that a canceled context is reported.
func TestMock_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := NewWithLabel(judge.LabelScraper, 0.75).Judge(ctx, batch("s00"))
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, got)
}
