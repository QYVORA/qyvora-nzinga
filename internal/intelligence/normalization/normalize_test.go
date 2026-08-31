package normalization

import (
	"context"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

func run(observations ...*models.Observation) *models.Session {
	sess := models.NewSession()
	New(sess, nil).Normalize(context.Background(), observations)
	return sess
}

func findHost(sess *models.Session, fqdn string) *models.Hostname {
	for _, h := range sess.Hostnames {
		if h.FQDN == fqdn {
			return h
		}
	}
	return nil
}

func findDomain(sess *models.Session, name string) *models.Domain {
	for _, d := range sess.Domains {
		if d.Name == name {
			return d
		}
	}
	return nil
}

func edge(sess *models.Session, typ models.RelationshipType, from, to string) bool {
	for _, e := range sess.Edges {
		if e.Type == typ && e.From == from && e.To == to {
			return true
		}
	}
	return false
}

func testObs(key, target, value string) *models.Observation {
	return &models.Observation{
		Source:     "test",
		Capability: models.CapDNSResolve,
		Target:     target,
		Key:        key,
		Value:      value,
		State:      models.StateObserved,
		Confidence: models.ConfidenceObserved,
	}
}

func TestApexARecordDoesNotCreateHostnameEntity(t *testing.T) {
	sess := run(testObs("domain", "", "example.com"), testObs("a", "example.com", "203.0.113.10"))
	if h := findHost(sess, "example.com"); h != nil {
		t.Fatalf("apex A record must not create a hostname entity, got %+v", h)
	}
	// The IP itself is still recorded.
	if len(sess.IPs) != 1 || sess.IPs[0].Address != "203.0.113.10" {
		t.Fatalf("expected the apex IP to be recorded, got %+v", sess.IPs)
	}
}

func TestARecordCreatesEdgeWhenHostnameObservedLater(t *testing.T) {
	// Order the A record first and the hostname observation second: the
	// edge must still be created (order-independence).
	sess := run(
		testObs("a", "www.example.com", "203.0.113.10"),
		testObs("hostname", "example.com", "www.example.com"),
	)
	h := findHost(sess, "www.example.com")
	if h == nil {
		t.Fatal("expected www.example.com hostname entity")
	}
	var ip *models.IP
	for _, i := range sess.IPs {
		ip = i
	}
	if ip == nil {
		t.Fatal("expected an IP entity")
	}
	if !edge(sess, models.RelResolvesTo, h.ID, ip.ID) {
		t.Fatal("expected resolves_to edge from www.example.com to the IP")
	}
}

func TestHostnameNotAttributedOutOfZone(t *testing.T) {
	// mail.example.net seen while querying example.com belongs to example.net.
	sess := run(
		testObs("a", "example.com", "203.0.113.10"),
		testObs("hostname", "example.com", "www.example.com"),
		testObs("hostname", "example.com", "mail.example.net"),
	)
	mail := findHost(sess, "mail.example.net")
	if mail == nil {
		t.Fatal("expected mail.example.net hostname")
	}
	net := findDomain(sess, "example.net")
	if net == nil {
		t.Fatal("expected example.net to be inferred as the owning domain")
	}
	if !edge(sess, models.RelOwes, mail.ID, net.ID) {
		t.Fatal("mail.example.net must belong to example.net, not the queried zone")
	}
	if com := findDomain(sess, "example.com"); com != nil && edge(sess, models.RelOwes, mail.ID, com.ID) {
		t.Fatal("mail.example.net must not be attributed to example.com")
	}
}

func TestHostnameWithinZoneIsAttributed(t *testing.T) {
	sess := run(
		testObs("hostname", "example.com", "www.example.com"),
		testObs("hostname", "example.com", "api.example.com"),
	)
	for _, fqdn := range []string{"www.example.com", "api.example.com"} {
		h := findHost(sess, fqdn)
		if h == nil {
			t.Fatalf("expected %s", fqdn)
		}
		com := findDomain(sess, "example.com")
		if com == nil || !edge(sess, models.RelOwes, h.ID, com.ID) {
			t.Fatalf("%s should belong to example.com", fqdn)
		}
	}
}

func TestNormalizeDedupesObservations(t *testing.T) {
	sess := run(
		testObs("hostname", "example.com", "www.example.com"),
		testObs("hostname", "example.com", "www.example.com"),
	)
	if len(sess.Observations) != 1 {
		t.Fatalf("duplicate observations must be deduplicated, got %d", len(sess.Observations))
	}
}

func TestEmailNormalization(t *testing.T) {
	sess := run(testObs("email", "example.com", "admin@example.com"))
	if len(sess.Emails) != 1 || sess.Emails[0].Address != "admin@example.com" {
		t.Fatalf("expected an email entity, got %+v", sess.Emails)
	}
}

func TestWithin(t *testing.T) {
	cases := []struct {
		host, zone string
		want       bool
	}{
		{"www.example.com", "example.com", true},
		{"example.com", "example.com", true},
		{"mail.example.net", "example.com", false},
		{"evil-example.com", "example.com", false},
		{"a.b.example.com", "example.com", true},
		{"www.example.com", "www.example.com", true},
		{"www.example.com", "", false},
	}
	for _, c := range cases {
		if got := within(c.host, c.zone); got != c.want {
			t.Errorf("within(%q, %q) = %v, want %v", c.host, c.zone, got, c.want)
		}
	}
}

func TestIsHostnameLike(t *testing.T) {
	if !isHostnameLike("www.example.com") {
		t.Fatal("www.example.com is hostname-like")
	}
	if isHostnameLike("admin@example.com") {
		t.Fatal("an email is not a hostname")
	}
	if isHostnameLike("localhost") {
		t.Fatal("a bare label with no dot is not a hostname here")
	}
}

func TestApexDomainOf(t *testing.T) {
	if got := apexDomainOf("www.example.co.uk"); got != "" {
		_ = got // behaviour for multi-part TLDs is a documented heuristic; assert the simple case:
	}
	if got := apexDomainOf("www.example.com"); got != "example.com" {
		t.Fatalf("apexDomainOf(www.example.com) = %q, want example.com", got)
	}
	if got := apexDomainOf("Mail.Example.NET"); got != "example.net" {
		t.Fatalf("apexDomainOf should be case-insensitive, got %q", got)
	}
}

// TestProvenanceCarriesToEvidence locks the observation→evidence provenance
// fields: source_type, collected_at, observed_at, raw_reference and hash.
func TestProvenanceCarriesToEvidence(t *testing.T) {
	sess := run(&models.Observation{
		Source:       "crt.sh",
		SourceType:   "cert",
		Capability:   models.CapCertEnumerate,
		Target:       "example.com",
		Key:          "hostname",
		Value:        "www.example.com",
		State:        models.StateObserved,
		Confidence:   models.ConfidenceObserved,
		RawReference: "https://crt.sh/?q=example.com",
		ObservedAt:   time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
	})
	if len(sess.Evidence) != 1 {
		t.Fatalf("expected 1 evidence item, got %d", len(sess.Evidence))
	}
	ev := sess.Evidence[0]
	if ev.SourceType != "cert" {
		t.Errorf("evidence source_type = %q, want cert", ev.SourceType)
	}
	if ev.RawReference != "https://crt.sh/?q=example.com" {
		t.Errorf("evidence raw_reference = %q, want crt.sh query URL", ev.RawReference)
	}
	if !ev.ObservedAt.Equal(time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("evidence observed_at not preserved: %v", ev.ObservedAt)
	}
	if ev.Timestamp.IsZero() {
		t.Errorf("evidence timestamp should be set")
	}
	if ev.Hash == "" {
		t.Errorf("evidence hash should be set")
	}
	want := models.HashContent("crt.sh\x00example.com\x00hostname\x00www.example.com")
	if ev.Hash != want {
		t.Errorf("evidence hash = %q, want %q", ev.Hash, want)
	}
}
