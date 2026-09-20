package rules

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
)

// suspect builds a suspect with the given bucketed features and evidence.
func suspect(id string, features detect.SemanticFeatures, evidence ...string) detect.Suspect {
	return detect.Suspect{
		SuspectID: id,
		Identity:  "10.0.0.1",
		Score:     9.5,
		Evidence:  evidence,
		Features:  features,
	}
}

// TestRules_Classify is the table that fixes every row of the spec §5.6 rules
// table and the precedence between rows.
func TestRules_Classify(t *testing.T) {
	tests := []struct {
		name       string
		suspect    detect.Suspect
		wantLabel  judge.Label
		wantConfid float64
	}{
		{
			name:       "scanner paths evidence is a vulnerability scanner",
			suspect:    suspect("s00", detect.SemanticFeatures{}, detect.EvidenceScannerPaths),
			wantLabel:  judge.LabelVulnerabilityScanner,
			wantConfid: 0.9,
		},
		{
			name: "scanner paths outranks auth failures",
			suspect: suspect("s00", detect.SemanticFeatures{
				AuthFailShare:  detect.ShareNearlyAll,
				RouteDiversity: detect.RoutesSingle,
			}, detect.EvidenceAuthFailRatioHigh, detect.EvidenceScannerPaths),
			wantLabel:  judge.LabelVulnerabilityScanner,
			wantConfid: 0.9,
		},
		{
			name:       "auth fail evidence is credential stuffing",
			suspect:    suspect("s00", detect.SemanticFeatures{}, detect.EvidenceAuthFailRatioHigh),
			wantLabel:  judge.LabelCredentialStuffing,
			wantConfid: 0.85,
		},
		{
			name: "auth failures outrank the hard ceiling",
			suspect: suspect("s00", detect.SemanticFeatures{
				RouteDiversity: detect.RoutesFew,
			}, detect.EvidenceAuthFailRatioHigh, detect.EvidenceRateOverHardCeiling),
			wantLabel:  judge.LabelCredentialStuffing,
			wantConfid: 0.85,
		},
		{
			name: "hard ceiling with few routes is a flood",
			suspect: suspect("s00", detect.SemanticFeatures{
				RouteDiversity: detect.RoutesFew,
			}, detect.EvidenceRateOverHardCeiling),
			wantLabel:  judge.LabelL7Flood,
			wantConfid: 0.85,
		},
		{
			name: "hard ceiling with a single route is a flood",
			suspect: suspect("s00", detect.SemanticFeatures{
				RouteDiversity: detect.RoutesSingle,
			}, detect.EvidenceRateOverHardCeiling),
			wantLabel:  judge.LabelL7Flood,
			wantConfid: 0.85,
		},
		{
			name: "hard ceiling across many routes is not a flood",
			suspect: suspect("s00", detect.SemanticFeatures{
				RouteDiversity:   detect.RoutesMany,
				TimingRegularity: detect.TimingMachineLikeRegular,
				Methods:          detect.MethodsMostlyGET,
			}, detect.EvidenceRateOverHardCeiling),
			wantLabel:  judge.LabelLegitimateBurst,
			wantConfid: 0.5,
		},
		{
			name: "enumerating beats the flood rule when routes are not few",
			suspect: suspect("s00", detect.SemanticFeatures{
				RouteDiversity:   detect.RoutesEnumerating,
				TimingRegularity: detect.TimingMachineLikeRegular,
				Methods:          detect.MethodsMostlyGET,
			}, detect.EvidenceRateOverHardCeiling),
			wantLabel:  judge.LabelScraper,
			wantConfid: 0.75,
		},
		{
			name: "enumerating regular GET is a scraper",
			suspect: suspect("s00", detect.SemanticFeatures{
				RouteDiversity:   detect.RoutesEnumerating,
				TimingRegularity: detect.TimingMachineLikeRegular,
				Methods:          detect.MethodsMostlyGET,
			}),
			wantLabel:  judge.LabelScraper,
			wantConfid: 0.75,
		},
		{
			name: "enumerating without machine timing is not a scraper",
			suspect: suspect("s00", detect.SemanticFeatures{
				RouteDiversity:   detect.RoutesEnumerating,
				TimingRegularity: detect.TimingHumanLikeIrregular,
				Methods:          detect.MethodsMostlyGET,
			}),
			wantLabel:  judge.LabelLegitimateBurst,
			wantConfid: 0.5,
		},
		{
			name: "enumerating regular POST is not a scraper",
			suspect: suspect("s00", detect.SemanticFeatures{
				RouteDiversity:   detect.RoutesEnumerating,
				TimingRegularity: detect.TimingMachineLikeRegular,
				Methods:          detect.MethodsMostlyPOSTLogin,
			}),
			wantLabel:  judge.LabelLegitimateBurst,
			wantConfid: 0.5,
		},
		{
			name: "high server errors on a single route is a misbehaving client",
			suspect: suspect("s00", detect.SemanticFeatures{
				ServerErrorShare: detect.ShareHigh,
				RouteDiversity:   detect.RoutesSingle,
			}),
			wantLabel:  judge.LabelMisbehavingClient,
			wantConfid: 0.75,
		},
		{
			name: "nearly all server errors on a single route is a misbehaving client",
			suspect: suspect("s00", detect.SemanticFeatures{
				ServerErrorShare: detect.ShareNearlyAll,
				RouteDiversity:   detect.RoutesSingle,
			}),
			wantLabel:  judge.LabelMisbehavingClient,
			wantConfid: 0.75,
		},
		{
			name: "moderate server errors on a single route is not misbehaving",
			suspect: suspect("s00", detect.SemanticFeatures{
				ServerErrorShare: detect.ShareModerate,
				RouteDiversity:   detect.RoutesSingle,
			}),
			wantLabel:  judge.LabelLegitimateBurst,
			wantConfid: 0.5,
		},
		{
			name: "server errors across few routes are not misbehaving",
			suspect: suspect("s00", detect.SemanticFeatures{
				ServerErrorShare: detect.ShareHigh,
				RouteDiversity:   detect.RoutesFew,
			}),
			wantLabel:  judge.LabelLegitimateBurst,
			wantConfid: 0.5,
		},
		{
			name: "declared bot with no evidence and no auth failures is benign",
			suspect: suspect("s00", detect.SemanticFeatures{
				ClientFamily:  clientFamilyBotDeclared,
				AuthFailShare: detect.ShareNone,
			}),
			wantLabel:  judge.LabelBenignCrawler,
			wantConfid: 0.6,
		},
		{
			name: "declared bot with any evidence is not benign",
			suspect: suspect("s00", detect.SemanticFeatures{
				ClientFamily:  clientFamilyBotDeclared,
				AuthFailShare: detect.ShareNone,
			}, detect.EvidencePrefixCampaign),
			wantLabel:  judge.LabelLegitimateBurst,
			wantConfid: 0.5,
		},
		{
			name: "declared bot with auth failures is not benign",
			suspect: suspect("s00", detect.SemanticFeatures{
				ClientFamily:  clientFamilyBotDeclared,
				AuthFailShare: detect.ShareLow,
			}),
			wantLabel:  judge.LabelLegitimateBurst,
			wantConfid: 0.5,
		},
		{
			name: "declared bot over the hard ceiling floods",
			suspect: suspect("s00", detect.SemanticFeatures{
				ClientFamily:   clientFamilyBotDeclared,
				AuthFailShare:  detect.ShareNone,
				RouteDiversity: detect.RoutesFew,
			}, detect.EvidenceRateOverHardCeiling),
			wantLabel:  judge.LabelL7Flood,
			wantConfid: 0.85,
		},
		{
			name:       "unclassified suspect is a legitimate burst",
			suspect:    suspect("s00", detect.SemanticFeatures{ClientFamily: detect.ClientNone}),
			wantLabel:  judge.LabelLegitimateBurst,
			wantConfid: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			label, confidence := classify(&tt.suspect)
			assert.Equal(t, tt.wantLabel, label)
			assert.InDelta(t, tt.wantConfid, confidence, 1e-9)
		})
	}
}

// TestRules_TableOrder pins the spec §5.6 rule order: first match wins, so the
// rows themselves are part of the contract.
func TestRules_TableOrder(t *testing.T) {
	want := []struct {
		label      judge.Label
		confidence float64
	}{
		{judge.LabelVulnerabilityScanner, 0.9},
		{judge.LabelCredentialStuffing, 0.85},
		{judge.LabelL7Flood, 0.85},
		{judge.LabelScraper, 0.75},
		{judge.LabelMisbehavingClient, 0.75},
		{judge.LabelBenignCrawler, 0.6},
		{judge.LabelLegitimateBurst, 0.5},
	}
	require.Len(t, ruleTable, len(want))
	for i, w := range want {
		assert.Equal(t, w.label, ruleTable[i].label, "row %d", i)
		assert.InDelta(t, w.confidence, ruleTable[i].confidence, 1e-9, "row %d", i)
	}
	assert.True(t, ruleTable[len(ruleTable)-1].match(&detect.Suspect{}), "last row must always match")
}

// TestRules_Judge checks the verdict envelope the controller consumes.
func TestRules_Judge(t *testing.T) {
	j := New()
	assert.Equal(t, "rules", j.Name())

	suspects := []detect.Suspect{
		suspect("s00", detect.SemanticFeatures{}, detect.EvidenceScannerPaths),
		suspect("s01", detect.SemanticFeatures{
			ClientFamily:  clientFamilyBotDeclared,
			AuthFailShare: detect.ShareNone,
		}),
	}
	got, err := j.Judge(context.Background(), suspects)
	require.NoError(t, err)
	require.Len(t, got, len(suspects))

	assert.Equal(t, judge.Verdict{
		SuspectID:     "s00",
		Label:         judge.LabelVulnerabilityScanner,
		Confidence:    0.9,
		Probabilities: probabilities(judge.LabelVulnerabilityScanner, 0.9),
		Judge:         "rules",
		Model:         "",
	}, got[0])
	assert.Equal(t, "s01", got[1].SuspectID)
	assert.Equal(t, judge.LabelBenignCrawler, got[1].Label)
	assert.InDelta(t, 0.6, got[1].Confidence, 1e-9)
	assert.Equal(t, "rules", got[1].Judge)
	assert.Empty(t, got[1].Model)
}

// TestRules_ProbabilitiesSumToOne checks the probability map shape: confidence
// on the chosen label, the rest spread evenly, summing to 1.
func TestRules_ProbabilitiesSumToOne(t *testing.T) {
	labels := judge.Labels()
	require.NotEmpty(t, labels)

	for _, r := range ruleTable {
		t.Run(string(r.label), func(t *testing.T) {
			p := probabilities(r.label, r.confidence)
			require.Len(t, p, len(labels))

			var sum float64
			for _, label := range labels {
				value, ok := p[label]
				require.True(t, ok, "missing label %q", label)
				sum += value
				if label == r.label {
					assert.InDelta(t, r.confidence, value, 1e-9)
					continue
				}
				assert.InDelta(t, (1-r.confidence)/float64(len(labels)-1), value, 1e-9)
			}
			assert.InDelta(t, 1, sum, 1e-9)
		})
	}
}

// TestRules_Deterministic checks that repeated runs over the same batch return
// identical verdicts, including the probability maps.
func TestRules_Deterministic(t *testing.T) {
	j := New()
	suspects := []detect.Suspect{
		suspect("s00", detect.SemanticFeatures{}, detect.EvidenceScannerPaths),
		suspect("s01", detect.SemanticFeatures{}, detect.EvidenceAuthFailRatioHigh),
		suspect("s02", detect.SemanticFeatures{RouteDiversity: detect.RoutesFew}, detect.EvidenceRateOverHardCeiling),
		suspect("s03", detect.SemanticFeatures{
			RouteDiversity:   detect.RoutesEnumerating,
			TimingRegularity: detect.TimingMachineLikeRegular,
			Methods:          detect.MethodsMostlyGET,
		}),
		suspect("s04", detect.SemanticFeatures{
			ServerErrorShare: detect.ShareNearlyAll,
			RouteDiversity:   detect.RoutesSingle,
		}),
		suspect("s05", detect.SemanticFeatures{
			ClientFamily:  clientFamilyBotDeclared,
			AuthFailShare: detect.ShareNone,
		}),
		suspect("s06", detect.SemanticFeatures{ClientFamily: detect.ClientNone}),
	}

	want, err := j.Judge(context.Background(), suspects)
	require.NoError(t, err)
	require.Len(t, want, len(suspects))

	for range 100 {
		got, err := j.Judge(context.Background(), suspects)
		require.NoError(t, err)
		assert.True(t, reflect.DeepEqual(want, got), "verdicts differ between runs")
	}
}

// TestRules_EmptyInput checks the batch boundary.
func TestRules_EmptyInput(t *testing.T) {
	got, err := New().Judge(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestRules_ContextCancelled checks that a canceled context is reported
// rather than silently ignored.
func TestRules_ContextCancelled(t *testing.T) {
	suspects := []detect.Suspect{suspect("s00", detect.SemanticFeatures{})}

	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		got, err := New().Judge(ctx, suspects)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, got)
	})

	t.Run("deadline exceeded", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()

		got, err := New().Judge(ctx, suspects)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, got)
	})
}
