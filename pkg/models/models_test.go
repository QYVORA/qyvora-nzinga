package models

import (
	"encoding/json"
	"testing"
)

func TestNewIDUniqueAndPrefixed(t *testing.T) {
	a := NewID("sess")
	b := NewID("sess")
	if a == b {
		t.Fatalf("expected distinct ids, got %q twice", a)
	}
	if len(a) == 0 || a[:5] != "sess-" {
		t.Fatalf("unexpected id shape %q", a)
	}
}

func TestHashContentDeterministic(t *testing.T) {
	h1 := HashContent("simulation\x00example.com\x00a\x00203.0.113.10")
	h2 := HashContent("simulation\x00example.com\x00a\x00203.0.113.10")
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %q vs %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("expected sha256 hex (64 chars), got %d", len(h1))
	}
	if HashContent("a\x00b") == HashContent("b\x00a") {
		t.Fatalf("hash must not be commutative over field order")
	}
}

func TestFindingFingerprintStabilityAndOrderIndependence(t *testing.T) {
	f1 := &Finding{RuleID: "OSINT-003", Category: "pii-exposure", Title: "Exposed email address x@example.com",
		Objects: []string{"b", "a"}, Attributes: map[string]string{"z": "1", "a": "2"}}
	f2 := &Finding{RuleID: "OSINT-003", Category: "pii-exposure", Title: "Exposed email address x@example.com",
		Objects: []string{"a", "b"}, Attributes: map[string]string{"a": "2", "z": "1"}}
	if f1.Fingerprint() != f2.Fingerprint() {
		t.Fatalf("fingerprints must not depend on map/slice order")
	}
	f3 := &Finding{RuleID: "OSINT-003", Category: "pii-exposure", Title: "Exposed email address y@example.com",
		Objects: []string{"a", "b"}}
	if f1.Fingerprint() == f3.Fingerprint() {
		t.Fatalf("different findings must differ")
	}
}

func TestSessionAddObservationDedupeIncludesTarget(t *testing.T) {
	s := NewSession()
	s.AddObservation(&Observation{Source: "simulation", Key: "a", Target: "example.com", Value: "203.0.113.10"})
	s.AddObservation(&Observation{Source: "simulation", Key: "a", Target: "www.example.com", Value: "203.0.113.10"})
	s.AddObservation(&Observation{Source: "simulation", Key: "a", Target: "www.example.com", Value: "203.0.113.10"})
	if len(s.Observations) != 2 {
		t.Fatalf("expected 2 distinct observations (target is part of identity), got %d", len(s.Observations))
	}
}

func TestSessionAddFindingMergesByFingerprint(t *testing.T) {
	s := NewSession()
	s.AddFinding(&Finding{RuleID: "OSINT-004", Category: "dns-wildcard", Title: "DNS wildcard in scope zone"})
	s.AddFinding(&Finding{RuleID: "OSINT-004", Category: "dns-wildcard", Title: "DNS wildcard in scope zone"})
	if len(s.Findings) != 1 {
		t.Fatalf("expected merged findings, got %d", len(s.Findings))
	}
}

func TestSessionPersistenceRoundtrip(t *testing.T) {
	s := NewSession()
	s.Target = "domain:example.com"
	s.RiskScore = 26
	s.RiskLevel = "low"
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back Session
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Target != s.Target || back.RiskScore != s.RiskScore {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", back, s)
	}
}

func TestConfidenceOrdering(t *testing.T) {
	if ConfidenceConfirmed.Rank() <= ConfidenceObserved.Rank() {
		t.Fatal("confirmed should rank above observed")
	}
	if ConfidenceNotObserved.Rank() >= ConfidenceUnknown.Rank() {
		t.Fatal("not_observed is the weakest claim")
	}
	if ConfidenceCombined := ConfidenceObserved.Combined(ConfidenceProbable); ConfidenceCombined != ConfidenceObserved {
		t.Fatal("combined should keep the stronger value")
	}
}
