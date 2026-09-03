package sources

import (
	"context"
	"testing"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

func TestAbuseIPDBContract(t *testing.T) {
	a := NewAbuseIPDB(nil, "")
	if a.ID() != "abuseipdb" || a.Name() == "" {
		t.Fatalf("bad source identity: %q %q", a.ID(), a.Name())
	}
	d := a.Describe()
	if !d.AuthRequired || !d.Public || d.Category != models.CategoryNetwork {
		t.Fatalf("bad Describe metadata: %+v", d)
	}
	if len(d.Targets) != 1 || d.Targets[0] != models.TargetIP {
		t.Fatalf("abuseipdb must target IP only, got %v", d.Targets)
	}
}

func TestAbuseIPDBSimulateCoveredIP(t *testing.T) {
	a := NewAbuseIPDB(nil, "")
	obs, err := a.Simulate(context.Background(), &models.Target{Type: models.TargetIP, Value: "203.0.113.10"})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if len(obs) < 2 {
		t.Fatalf("simulate produced %d observations, want score+reports", len(obs))
	}
	seenScore := false
	for _, o := range obs {
		if o.Source != "abuseipdb" || o.Target != "203.0.113.10" {
			t.Fatalf("observation lost source/target: %+v", o)
		}
		if o.Key == "ip.abuse.score" && o.Value == "15" {
			seenScore = true
		}
	}
	if !seenScore {
		t.Fatalf("expected ip.abuse.score=15 in %+v", obs)
	}
}

func TestAbuseIPDBSimulateHonestNegative(t *testing.T) {
	a := NewAbuseIPDB(nil, "")
	obs, err := a.Simulate(context.Background(), &models.Target{Type: models.TargetIP, Value: "198.51.100.5"})
	if err != nil {
		t.Fatalf("simulate should not error for an uncovered address, got %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("uncovered address must yield no observations, got %d", len(obs))
	}
}

func TestAbuseIPDBSimulateIgnoresNonIPTarget(t *testing.T) {
	a := NewAbuseIPDB(nil, "")
	obs, err := a.Simulate(context.Background(), &models.Target{Type: models.TargetDomain, Value: "example.com"})
	if err != nil || len(obs) != 0 {
		t.Fatalf("domain target must be ignored: obs=%d err=%v", len(obs), err)
	}
}

func TestAbuseIPDBCollectDegradesWithoutKey(t *testing.T) {
	a := NewAbuseIPDB(nil, "")
	_, err := a.Collect(context.Background(), &models.Target{Type: models.TargetIP, Value: "203.0.113.10"})
	if err == nil {
		t.Fatal("expect an error without a client")
	}
	a = NewAbuseIPDB(&Client{}, "")
	_, err = a.Collect(context.Background(), &models.Target{Type: models.TargetIP, Value: "203.0.113.10"})
	if err == nil {
		t.Fatal("expect an error without an API key")
	}
	_, err = a.Collect(context.Background(), &models.Target{Type: models.TargetIP, Value: "not-an-ip"})
	if err == nil {
		t.Fatal("expect an error for an invalid IP")
	}
	obs, err := a.Collect(context.Background(), &models.Target{Type: models.TargetDomain, Value: "example.com"})
	if err != nil || len(obs) != 0 {
		t.Fatalf("non-IP target must be ignored: obs=%d err=%v", len(obs), err)
	}
}

func TestAbuseIPDBRegistryRunsSimulatedOnIPTarget(t *testing.T) {
	reg := NewRegistry(NewAbuseIPDB(nil, ""), NewSimulation())
	target := &models.Target{Type: models.TargetIP, Value: "203.0.113.10", Auth: models.Authorization{Granted: true}}
	obs, errs := reg.RunMode(context.Background(), nil, target, []string{"abuseipdb", "simulation"}, true)
	if len(errs) != 0 {
		t.Fatalf("simulated run produced errors: %v", errs)
	}
	var rep int
	for _, o := range obs {
		if o.Source == "abuseipdb" {
			rep++
		}
	}
	if rep == 0 {
		t.Fatalf("expected abuseipdb reputation observations in the simulated run, got %d total", len(obs))
	}
}

func TestAbuseIPDBRegistryUnauthorizedTargetRecorded(t *testing.T) {
	reg := NewRegistry(NewAbuseIPDB(nil, ""), NewSimulation())
	obs, errs := reg.RunMode(context.Background(), nil, &models.Target{Type: models.TargetIP, Value: "203.0.113.10"}, []string{"abuseipdb", "simulation"}, true)
	if len(errs) == 0 {
		t.Fatal("abuseipdb is a live source and must refuse an unauthorized target")
	}
	var rep int
	for _, o := range obs {
		if o.Source == "abuseipdb" {
			rep++
		}
	}
	if rep != 0 {
		t.Fatalf("unauthorized target must not yield abuseipdb observations, got %d", rep)
	}
}
