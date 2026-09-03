package correlation

import (
	"testing"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// correlationSession returns a session whose normalized entities exercise the
// three claim families currently produced: identity (multi-platform username),
// exposure (email in a registry source), and infrastructure (two domains whose
// hostnames resolve to the same address).
func correlationSession() *models.Session {
	return &models.Session{
		ID:     "sess-corr",
		Target: "domain:example.com",
		Domains: []*models.Domain{
			{ID: "dom-1", Name: "example.com"},
			{ID: "dom-2", Name: "example.net"},
		},
		Usernames: []*models.Username{
			{ID: "usr-1", Handle: "alice", Platforms: []string{"github", "gitlab", "twitter"}},
			{ID: "usr-2", Handle: "bob", Platforms: []string{"github"}},
		},
		IPs: []*models.IP{
			{ID: "ip-1", Address: "203.0.113.10"},
		},
		Emails: []*models.Email{
			{ID: "eml-1", Address: "admin@example.com"},
		},
		Observations: []*models.Observation{
			{ID: "obs-u1", Source: "simulation", Key: "username", Target: "github", Value: "alice"},
			{ID: "obs-u2", Source: "simulation", Key: "username", Target: "gitlab", Value: "alice"},
			{ID: "obs-u3", Source: "simulation", Key: "username", Target: "twitter", Value: "alice"},
			{ID: "obs-em1", Source: "whois", Key: "email", Target: "example.com", Value: "admin@example.com"},
			{ID: "obs-a1", Source: "simulation", Key: "a", Target: "www.example.com", Value: "203.0.113.10"},
			{ID: "obs-a2", Source: "simulation", Key: "a", Target: "mail.example.net", Value: "203.0.113.10"},
		},
		Edges: []*models.Edge{
			{From: "hst-1", To: "dom-1", Type: models.RelOwes},
			{From: "hst-2", To: "dom-2", Type: models.RelOwes},
			{From: "hst-1", To: "ip-1", Type: models.RelResolvesTo},
			{From: "hst-2", To: "ip-1", Type: models.RelResolvesTo},
		},
	}
}

func TestRunProducesIdentityClaimForMultiPlatformUsername(t *testing.T) {
	sess := correlationSession()
	claims := New(nil).Run(sess)
	var found bool
	for _, c := range claims {
		if c.Type == models.ClaimIdentity && c.Subject == "alice" {
			found = true
			if len(c.ObservationIDs) < 3 {
				t.Fatalf("identity claim should reference 3 platform observations, got %d", len(c.ObservationIDs))
			}
		}
	}
	if !found {
		t.Fatal("expected an identity claim for alice (3 platforms)")
	}
	// A single-platform username must not produce an identity claim.
	for _, c := range claims {
		if c.Type == models.ClaimIdentity && c.Subject == "bob" {
			t.Fatal("bob has only one platform and must not yield an identity claim")
		}
	}
}

func TestRunProducesExposureClaimFromRegistrySource(t *testing.T) {
	sess := correlationSession()
	claims := New(nil).Run(sess)
	var found bool
	for _, c := range claims {
		if c.Type == models.ClaimExposure && c.Subject == "admin@example.com" {
			found = true
			if c.Confidence != models.ConfidenceObserved {
				t.Fatalf("exposure confidence=%s want observed", c.Confidence)
			}
		}
	}
	if !found {
		t.Fatal("expected an exposure claim for admin@example.com from whois")
	}
}

func TestRunProducesInfrastructureClaimForSharedHosting(t *testing.T) {
	sess := correlationSession()
	claims := New(nil).Run(sess)
	var found bool
	for _, c := range claims {
		if c.Type == models.ClaimInfrastructure && c.Subject == "203.0.113.10" {
			found = true
			if len(c.ObservationIDs) < 2 {
				t.Fatalf("infrastructure claim should reference both A-record observations, got %d", len(c.ObservationIDs))
			}
		}
	}
	if !found {
		t.Fatal("expected an infrastructure claim for shared hosting on 203.0.113.10")
	}
}

func TestRunIsDeterministicAndStoresClaims(t *testing.T) {
	sess := correlationSession()
	first := New(nil).Run(sess)
	second := New(nil).Run(correlationSession())
	if len(first) != len(second) {
		t.Fatalf("claim counts differ: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Assertion != second[i].Assertion || first[i].Type != second[i].Type {
			t.Fatalf("claim %d order/content differed", i)
		}
	}
	if len(sess.Claims) != len(first) {
		t.Fatalf("claims not stored on session: stored=%d produced=%d", len(sess.Claims), len(first))
	}
}

func TestRunDegradesOnEmptySession(t *testing.T) {
	if got := New(nil).Run(models.NewSession()); len(got) != 0 {
		t.Fatalf("empty session produced %d claims, want 0", len(got))
	}
	if got := New(nil).Run(nil); got != nil {
		t.Fatalf("nil session should yield nil claims, got %v", got)
	}
}
