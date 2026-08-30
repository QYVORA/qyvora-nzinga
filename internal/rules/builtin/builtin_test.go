package builtin

import (
	"testing"
	"time"

	"github.com/QYVORA/qyvora-nzinga/internal/rules"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// helperSession returns a session with one domain, one hostname and two IPs.
func helperSession() *models.Session {
	return &models.Session{
		ID:      "sess-1",
		Target:  "domain:example.com",
		Domains: []*models.Domain{{ID: "dom-1", Name: "example.com"}},
		Hostnames: []*models.Hostname{
			{ID: "hst-1", FQDN: "www.example.com"},
			{ID: "hst-2", FQDN: "mail.example.net"},
		},
		IPs: []*models.IP{
			{ID: "ip-1", Address: "203.0.113.10"},
			{ID: "ip-2", Address: "2001:db8::10"},
		},
	}
}

func engine() *rules.Engine { return rules.NewEngine().AddMany(All()) }

func TestEngineDeterministicOrder(t *testing.T) {
	sess := helperSession()
	sess.Attributes = map[string]string{"dns.wildcard": "true"}
	sess.Observations = []*models.Observation{
		{Source: "simulation", Key: "dns.wildcard", Value: "true"},
	}
	first := engine().Eval(rules.NewContext(sess), "tgt-1", "sess-1")
	second := engine().Eval(rules.NewContext(sess), "tgt-1", "sess-1")
	if len(first) != len(second) {
		t.Fatalf("same input, different findings: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Title != second[i].Title || first[i].RuleID != second[i].RuleID {
			t.Fatalf("order changed between runs: %+v vs %+v", first[i], second[i])
		}
	}
	// Severity descending, then rule id.
	if len(first) > 1 && first[0].Severity.Weights() < first[1].Severity.Weights() {
		t.Fatalf("findings not sorted by severity desc")
	}
}

func TestInfrastructureOverlapFiresRegression(t *testing.T) {
	sess := helperSession()
	sess.Domains = append(sess.Domains, &models.Domain{ID: "dom-2", Name: "example.net"})
	sess.Edges = []*models.Edge{
		{From: "hst-1", To: "dom-1", Type: models.RelOwes},
		{From: "hst-2", To: "dom-2", Type: models.RelOwes},
		{From: "hst-1", To: "ip-1", Type: models.RelResolvesTo},
		{From: "hst-2", To: "ip-1", Type: models.RelResolvesTo},
	}
	sess.Observations = []*models.Observation{
		{Source: "simulation", Key: "a", Target: "www.example.com", Value: "203.0.113.10"},
		{Source: "simulation", Key: "a", Target: "mail.example.net", Value: "203.0.113.10"},
	}
	findings := engine().Eval(rules.NewContext(sess), "tgt-1", "sess-1")
	var overlap *models.Finding
	for _, f := range findings {
		if f.RuleID == "OSINT-002" {
			overlap = f
		}
	}
	if overlap == nil {
		t.Fatal("OSINT-002 should fire when two domains' hostnames share an IP")
	}
	// The finding must reference the address, never the entity id.
	if overlap.Attributes["ip"] != "203.0.113.10" {
		t.Fatalf("expected address in finding attributes, got %q", overlap.Attributes["ip"])
	}
	if len(overlap.Evidence) == 0 {
		t.Fatal("finding should carry evidence")
	}
}

func TestInfrastructureOverlapRequiresTwoDomains(t *testing.T) {
	sess := helperSession()
	sess.Edges = []*models.Edge{
		{From: "hst-1", To: "dom-1", Type: models.RelOwes},
		{From: "hst-1", To: "ip-1", Type: models.RelResolvesTo},
	}
	findings := engine().Eval(rules.NewContext(sess), "tgt-1", "sess-1")
	for _, f := range findings {
		if f.RuleID == "OSINT-002" {
			t.Fatal("OSINT-002 must not fire for a single domain")
		}
	}
}

func TestExposedPIIEmailFiresOnWhoisOrCert(t *testing.T) {
	sess := helperSession()
	sess.Emails = []*models.Email{{ID: "eml-1", Address: "admin@example.com"}}
	sess.Observations = []*models.Observation{
		{Source: "whois", Key: "email", Value: "admin@example.com"},
	}
	findings := engine().Eval(rules.NewContext(sess), "tgt-1", "sess-1")
	if !hasRule(findings, "OSINT-003") {
		t.Fatal("OSINT-003 should fire for a whois-exposed email")
	}
}

func TestExposedPIIEmailNotFiredWithoutRegistrySource(t *testing.T) {
	sess := helperSession()
	sess.Emails = []*models.Email{{ID: "eml-1", Address: "admin@example.com"}}
	sess.Observations = []*models.Observation{
		{Source: "simulation", Key: "email", Value: "admin@example.com"},
	}
	findings := engine().Eval(rules.NewContext(sess), "tgt-1", "sess-1")
	if hasRule(findings, "OSINT-003") {
		t.Fatal("OSINT-003 must not fire without a whois/crt.sh source")
	}
}

func TestUsernameReuseRequiresTwoPlatforms(t *testing.T) {
	sess := helperSession()
	sess.Usernames = []*models.Username{{ID: "usr-1", Handle: "alice", Platforms: []string{"github", "twitter"}}}
	sess.Observations = []*models.Observation{
		{Source: "github", Key: "username", Value: "alice"},
		{Source: "twitter", Key: "username", Value: "alice"},
	}
	findings := engine().Eval(rules.NewContext(sess), "tgt-1", "sess-1")
	if !hasRule(findings, "OSINT-001") {
		t.Fatal("OSINT-001 should fire when a handle appears on two platforms")
	}

	sess2 := helperSession()
	sess2.Usernames = []*models.Username{{ID: "usr-2", Handle: "bob", Platforms: []string{"github"}}}
	sess2.Observations = []*models.Observation{{Source: "github", Key: "username", Value: "bob"}}
	findings2 := engine().Eval(rules.NewContext(sess2), "tgt-1", "sess-1")
	if hasRule(findings2, "OSINT-001") {
		t.Fatal("OSINT-001 must not fire for a single platform")
	}
}

func TestDNSWildcardFiresOnSessionAttributeAndObservation(t *testing.T) {
	sess := helperSession()
	sess.Attributes = map[string]string{"dns.wildcard": "true"}
	sess.Observations = []*models.Observation{
		{Source: "simulation", Key: "dns.wildcard", Value: "true"},
	}
	findings := engine().Eval(rules.NewContext(sess), "tgt-1", "sess-1")
	if !hasRule(findings, "OSINT-004") {
		t.Fatal("OSINT-004 should fire on a wildcard observation")
	}

	sess2 := helperSession()
	findings2 := engine().Eval(rules.NewContext(sess2), "tgt-1", "sess-1")
	if hasRule(findings2, "OSINT-004") {
		t.Fatal("OSINT-004 must not fire without wildcard evidence")
	}
}

func hasRule(findings []*models.Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestRuleContractFieldsPresent(t *testing.T) {
	for _, r := range All() {
		if r.ID == "" || r.Name == "" || r.Detect == nil || r.Severity == "" {
			t.Fatalf("rule %q is missing contract fields", r.ID)
		}
		if !r.Confidence.Valid() {
			t.Fatalf("rule %q has invalid confidence %q", r.ID, r.Confidence)
		}
		if r.Severity.Weights() <= 0 && r.Severity != models.SeverityInformational {
			t.Fatalf("rule %q has invalid severity %q", r.ID, r.Severity)
		}
	}
}

func TestEvidenceForObservationPreservesProvenance(t *testing.T) {
	o := &models.Observation{Source: "crt.sh", Target: "example.com", Key: "hostname", Value: "www.example.com", State: models.StateObserved}
	ev := rules.EvidenceForObservation(o)
	_ = time.Now()
	if ev.Source != "crt.sh" || ev.Data != "hostname=www.example.com" || ev.Hash == "" {
		t.Fatalf("evidence lost provenance: %+v", ev)
	}
}
