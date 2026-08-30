package risk

import (
	"context"
	"testing"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

func TestLevelThresholds(t *testing.T) {
	cases := map[int]string{
		0:   "none",
		1:   "low",
		34:  "low",
		35:  "medium",
		59:  "medium",
		60:  "high",
		79:  "high",
		80:  "critical",
		100: "critical",
	}
	for score, want := range cases {
		if got := Level(score); got != want {
			t.Errorf("Level(%d) = %q, want %q", score, got, want)
		}
	}
}

func TestScoreForBounded(t *testing.T) {
	f := &models.Finding{
		Severity:   models.SeverityCritical,
		Confidence: models.ConfidenceConfirmed,
		Category:   "pii-exposure",
	}
	r := ScoreFor(f)
	if r.Score < 0 || r.Score > MaxScore {
		t.Fatalf("score out of range: %d", r.Score)
	}
	if r.Exposure != 4 {
		t.Fatal("pii-exposure should carry exposure=4")
	}
	if r.Severity != models.SeverityCritical || r.Confidence != models.ConfidenceConfirmed {
		t.Fatal("risk must preserve severity/confidence")
	}
	if r.Rationale == "" {
		t.Fatal("rationale must explain the score")
	}
}

func TestScoreForCategories(t *testing.T) {
	pii := ScoreFor(&models.Finding{Severity: models.SeverityMedium, Confidence: models.ConfidenceObserved, Category: "pii-exposure"})
	cons := ScoreFor(&models.Finding{Severity: models.SeverityMedium, Confidence: models.ConfidenceObserved, Category: "identity-reuse"})
	if pii.Score <= cons.Score {
		t.Fatalf("pii exposure should outrank identity-consistency: %d vs %d", pii.Score, cons.Score)
	}
}

func TestScoreForNil(t *testing.T) {
	if got := ScoreFor(nil); got.Score != 0 {
		t.Fatalf("nil finding should score 0, got %d", got.Score)
	}
}

func TestAssessExcludesFalsePositives(t *testing.T) {
	a := &Assessor{}
	active := &models.Finding{Severity: models.SeverityHigh, Confidence: models.ConfidenceObserved, Status: models.StatusDetected, Category: "network"}
	fp := &models.Finding{Severity: models.SeverityCritical, Confidence: models.ConfidenceConfirmed, Status: models.StatusFalsePositive, Category: "network"}
	score, level := a.Assess(context.Background(), []*models.Finding{active, fp})
	if score <= 0 {
		t.Fatal("active findings must still count")
	}
	onlyFP, _ := a.Assess(context.Background(), []*models.Finding{fp})
	onlyResolved, _ := a.Assess(context.Background(), []*models.Finding{{
		Severity: models.SeverityCritical, Confidence: models.ConfidenceConfirmed, Status: models.StatusResolved, Category: "network",
	}})
	if onlyFP != 0 || onlyResolved != 0 {
		t.Fatalf("excluded findings must not contribute to risk: %d, %d", onlyFP, onlyResolved)
	}
	_ = level
}

func TestAssessEmpty(t *testing.T) {
	a := &Assessor{}
	score, level := a.Assess(context.Background(), nil)
	if score != 0 || level != "none" {
		t.Fatalf("empty assessment should be none/0, got %d/%q", score, level)
	}
}

func TestConfidenceValueMapping(t *testing.T) {
	if confidenceValue(models.ConfidenceConfirmed) != 1.0 {
		t.Fatal("confirmed must map to 1.0")
	}
	if confidenceValue(models.ConfidenceNotObserved) != 0.1 {
		t.Fatal("not_observed must map to the weakest weight")
	}
}
