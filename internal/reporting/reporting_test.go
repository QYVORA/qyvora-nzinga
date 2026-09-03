package reporting

import (
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

func reportSession() *models.Session {
	return &models.Session{
		ID:     "sess-rpt",
		Target: "domain:example.com",
		Observations: []*models.Observation{
			{ID: "obs-1", Source: "whois", Key: "email", Target: "example.com", Value: "admin@example.com"},
			{ID: "obs-2", Source: "simulation", Key: "a", Target: "www.example.com", Value: "203.0.113.10"},
		},
		Claims: []*models.Claim{
			{
				ID: "clm-1", Type: models.ClaimExposure, Subject: "admin@example.com",
				Assertion:  "email admin@example.com is recoverable from public sources",
				Confidence: models.ConfidenceObserved, State: models.StateObserved,
				ObservationIDs: []string{"obs-1"},
			},
		},
		Findings: []*models.Finding{
			{RuleID: "OSINT-005", Title: "Correlation claim surfaced", Severity: models.SeverityMedium, Confidence: models.ConfidenceObserved},
		},
	}
}

func TestRenderTerminalSurfacesClaims(t *testing.T) {
	out, err := Render(reportSession(), FormatTerminal)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"claims (1)", "Correlation claim surfaced", "exposure", "admin@example.com", "observed"} {
		if !strings.Contains(out, want) {
			t.Fatalf("terminal report missing %q\n%s", want, out)
		}
	}
}

func TestRenderMarkdownSurfacesClaims(t *testing.T) {
	out, err := Render(reportSession(), FormatMarkdown)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Correlation claims (1)", "| type | subject | assertion | confidence | observations |", "exposure", "admin@example.com"} {
		if !strings.Contains(out, want) {
			t.Fatalf("markdown report missing %q\n%s", want, out)
		}
	}
}

func TestRenderClaimsAbsentProduceNoSection(t *testing.T) {
	sess := reportSession()
	sess.Claims = nil
	out, err := Render(sess, FormatMarkdown)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "Correlation claims") {
		t.Fatalf("markdown report must omit the claims section when empty\n%s", out)
	}
	if strings.Contains(out, "claims (0)") {
		t.Fatalf("terminal report must omit claims block when empty\n%s", out)
	}
}
