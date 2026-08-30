package sources

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// simulation is the offline deterministic dataset. It is the only source that
// runs without authorization and the only source that never touches the
// network. Its output must remain byte-stable so the demo, tests and reports
// are reproducible.
type simulation struct{}

// NewSimulation returns the simulation source.
func NewSimulation() *simulation { return &simulation{} }

// ID implements Source.
func (s *simulation) ID() string { return "simulation" }

// Name implements Source.
func (s *simulation) Name() string { return "Offline simulation dataset" }

// Capabilities implements Source.
func (s *simulation) Capabilities() []models.Capability {
	return []models.Capability{
		models.CapDomainEnumerate,
		models.CapSubdomainEnumerate,
		models.CapDNSResolve,
		models.CapWhoisLookup,
		models.CapCertEnumerate,
		models.CapUsernameLookup,
		models.CapRepoEnumerate,
		models.CapEmailEnumerate,
	}
}

// Describe implements Source.
func (s *simulation) Describe() models.Source {
	return models.Source{
		ID:           "simulation",
		Name:         "Offline simulation dataset",
		Description:  "Deterministic offline dataset for demo runs; runs without authorization and never touches the network",
		Category:     models.CategorySimulation,
		Capabilities: s.Capabilities(),
		Output: []models.NodeKind{models.NodeDomain, models.NodeHostname, models.NodeIP,
			models.NodeEmail, models.NodeUsername, models.NodeRepository,
			models.NodeCertificate, models.NodeOrganization},
		Risk:         models.RiskS1,
		AuthRequired: false,
		Public:       false,
		Targets: []models.TargetType{models.TargetDomain, models.TargetOrganization,
			models.TargetUsername, models.TargetIP, models.TargetInfrastructure},
	}
}

// Collect implements Source (Simulate is the live path for this source).
func (s *simulation) Collect(ctx context.Context, t *models.Target) ([]*models.Observation, error) {
	return s.Simulate(ctx, t)
}

// Simulate implements Source: yields the offline dataset for the recognized
// demo targets.
func (s *simulation) Simulate(ctx context.Context, t *models.Target) ([]*models.Observation, error) {
	if t == nil {
		return nil, fmt.Errorf("target is nil")
	}
	var out []*models.Observation
	switch t.Type {
	case models.TargetDomain, models.TargetInfrastructure:
		d := normalizeHost(t.Value)
		if isExampleDomain(d) || d == "example.com" || d == "example.net" || d == "example.org" {
			out = append(out, simulatedDomainObservations(d)...)
			out = append(out, simulatedDNSObservations(d)...)
			out = append(out, simulatedWhoisObservations(d)...)
			out = append(out, simulatedCertObservations(d)...)
		} else {
			return nil, fmt.Errorf("the offline dataset covers example.com, example.net and example.org only")
		}
	case models.TargetOrganization:
		out = append(out, simulatedOrgObservations(foldOrg(t.Value))...)
	case models.TargetUsername:
		out = append(out, simulatedUserObservations(t.Value)...)
	case models.TargetIP:
		ip := strings.TrimSpace(t.Value)
		if net.ParseIP(ip) != nil && ip == "203.0.113.10" {
			return simulatedIPObservations(ip), nil
		}
		return nil, fmt.Errorf("the offline dataset covers 203.0.113.10 only")
	default:
		return nil, fmt.Errorf("unsupported target type %q", t.Type)
	}
	return out, nil
}

func simulatedIPObservations(ip string) []*models.Observation {
	now := time.Now().UTC()
	out := []*models.Observation{
		obs("simulation", models.CapIPLookup, "ip", ip, ip, nil),
		obs("simulation", models.CapDNSResolve, "hostname", ip, "www.example.com", nil),
		obs("simulation", models.CapDNSResolve, "hostname", ip, "api.example.com", nil),
		obs("simulation", models.CapASNLookup, "asn", ip, "64500", map[string]string{"owner": "Example Corp"}),
	}
	for _, o := range out {
		o.Timestamp = now
	}
	return out
}

// isExampleDomain reports whether d is one of the documented demo domains.
func isExampleDomain(d string) bool {
	switch d {
	case "example.com", "example.net", "example.org":
		return true
	default:
		return false
	}
}

// foldOrg normalizes organization aliases to the canonical "Example Corp".
func foldOrg(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "example", "example corp", "example-corp", "example corporation":
		return "Example Corp"
	default:
		return "Example Corp"
	}
}

func obs(source string, cap models.Capability, key, target, value string, raw map[string]string) *models.Observation {
	return &models.Observation{
		ID:         models.NewID("obs"),
		Source:     source,
		Capability: cap,
		Target:     target,
		Key:        key,
		Value:      value,
		State:      models.StateObserved,
		Confidence: models.ConfidenceObserved,
		Raw:        raw,
		Timestamp:  time.Now().UTC(),
	}
}

func simulatedDomainObservations(domain string) []*models.Observation {
	now := time.Now().UTC()
	dom := []*models.Observation{
		obs("simulation", models.CapDomainEnumerate, "domain", domain, domain, nil),
		obs("simulation", models.CapDomainEnumerate, "registrant", domain, "Example Corp", map[string]string{"source": "registry"}),
	}
	for _, h := range []string{"blog", "dev", "files", "remote", "status", "vpn"} {
		dom = append(dom, obs("simulation", models.CapSubdomainEnumerate, "hostname", domain, h+"."+domain, nil))
	}
	// Discovering mail.example.net from example.com's certificate points at a
	// second domain in the same estate (relationship input for correlation).
	dom = append(dom, obs("simulation", models.CapSubdomainEnumerate, "hostname", domain, "mail.example.net", nil))
	for _, o := range dom {
		o.Timestamp = now
	}
	return dom
}

func simulatedDNSObservations(domain string) []*models.Observation {
	now := time.Now().UTC()
	var out []*models.Observation
	// Apex and www resolve; staging resolves only for example.net (no wildcard
	// there — see the wildcard observation below for example.com).
	apexIP := "203.0.113.10"
	wwwIP := "203.0.113.10"
	if domain == "example.org" {
		apexIP = "203.0.113.20"
		wwwIP = "203.0.113.20"
	}
	add := func(o *models.Observation) { out = append(out, o) }
	add(obs("simulation", models.CapDNSResolve, "a", domain, apexIP, nil))
	add(obs("simulation", models.CapDNSResolve, "a", "www."+domain, wwwIP, nil))
	add(obs("simulation", models.CapDNSResolve, "aaaa", "www."+domain, "2001:db8::10", nil))
	add(obs("simulation", models.CapDNSResolve, "nameserver", domain, "ns1.example.net", nil))
	add(obs("simulation", models.CapDNSResolve, "nameserver", domain, "ns2.example.net", nil))
	add(obs("simulation", models.CapDNSResolve, "mx", domain, "mail."+domain, nil))
	add(obs("simulation", models.CapDNSResolve, "txt", domain, "v=spf1 include:_spf.example.net -all", nil))
	// The demo's example.com runs a DNS wildcard: the "dns.wildcard"
	// observation records a positive finding in dataset form. The sibling
	// example.net / example.org zones do not wildcard.
	if domain == "example.com" {
		add(obs("simulation", models.CapDNSResolve, "dns.wildcard", domain, "true", map[string]string{"host": "junk." + domain, "resolved": "203.0.113.10"}))
	}
	// Shared hosting: mail.example.net (discovered via example.com's crt.sh
	// SANs) resolves onto the same 203.0.113.10 as www.example.com, tying
	// example.net to example.com's hosting — the OSINT-002 input.
	if domain == "example.com" {
		add(obs("simulation", models.CapDNSResolve, "a", "mail.example.net", "203.0.113.10", nil))
	}
	// Shared hosting: example.net's www also lands on 203.0.113.10.
	if domain == "example.net" {
		add(obs("simulation", models.CapDNSResolve, "a", "www."+domain, "203.0.113.10", nil))
		add(obs("simulation", models.CapDNSResolve, "mx", domain, "mail."+domain, nil))
		// The sibling host referenced by example.net's certificates resolves
		// onto the same shared address, exposing the overlap from this side.
		add(obs("simulation", models.CapDNSResolve, "a", "mail.example.com", "203.0.113.10", nil))
	}
	_ = now
	return out
}

func simulatedWhoisObservations(domain string) []*models.Observation {
	now := time.Now().UTC()
	var out []*models.Observation
	switch domain {
	case "example.com":
		out = append(out,
			obs("simulation", models.CapWhoisLookup, "registrant", domain, "Example Corp", map[string]string{"registrar": "Example Registrar Inc", "created": "1995-08-14"}),
			obs("simulation", models.CapWhoisLookup, "email", domain, "abuse@example.com", map[string]string{"field": "Registrant Abuse Contact"}),
			obs("simulation", models.CapWhoisLookup, "email", domain, "admin@example.com", map[string]string{"field": "Registrant Email"}),
		)
	case "example.net":
		out = append(out,
			obs("simulation", models.CapWhoisLookup, "registrant", domain, "Example Corp", map[string]string{"registrar": "Example Registrar Inc", "created": "1995-08-14"}),
			obs("simulation", models.CapWhoisLookup, "email", domain, "abuse@example.com", map[string]string{"field": "Registrant Abuse Contact"}),
		)
	case "example.org":
		out = append(out,
			obs("simulation", models.CapWhoisLookup, "registrant", domain, "IANA", map[string]string{"registrar": "Not applicable"}),
		)
	}
	for _, o := range out {
		o.Timestamp = now
	}
	return out
}

func simulatedOrgObservations(org string) []*models.Observation {
	now := time.Now().UTC()
	out := []*models.Observation{
		obs("simulation", models.CapDomainEnumerate, "organization", org, org, nil),
		obs("simulation", models.CapDomainEnumerate, "owned_domain", org, "example.com", nil),
		obs("simulation", models.CapDomainEnumerate, "owned_domain", org, "example.net", nil),
		obs("simulation", models.CapRepoEnumerate, "org_repo", "github", "example-corp/widget", map[string]string{"stars": "128"}),
		obs("simulation", models.CapUsernameLookup, "org_repo", "github", "github.com/example-corp", nil),
	}
	for _, o := range out {
		o.Timestamp = now
	}
	return out
}

func simulatedUserObservations(handle string) []*models.Observation {
	now := time.Now().UTC()
	h := strings.ToLower(strings.TrimSpace(handle))
	if h == "" {
		h = "alice"
	}
	var out []*models.Observation
	switch h {
	case "alice":
		out = []*models.Observation{
			obs("simulation", models.CapUsernameLookup, "username", "github", "alice", map[string]string{"url": "https://github.com/alice"}),
			obs("simulation", models.CapUsernameLookup, "username", "twitter", "alice", map[string]string{"url": "https://twitter.com/alice"}),
			obs("simulation", models.CapUsernameLookup, "username", "gitlab", "alice", map[string]string{"url": "https://gitlab.com/alice"}),
			obs("simulation", models.CapUsernameLookup, "person_name", "github", "Alice A. Example", map[string]string{"url": "https://github.com/alice"}),
			obs("simulation", models.CapUsernameLookup, "github_company", "github", "Example Corp", map[string]string{"url": "https://github.com/alice"}),
			obs("simulation", models.CapUsernameLookup, "email", "github", "alice@example.com", nil),
			obs("simulation", models.CapRepoEnumerate, "repo", "github", "alice/toolkit", map[string]string{"stars": "245", "url": "https://github.com/alice/toolkit"}),
			obs("simulation", models.CapRepoEnumerate, "repo", "github", "alice/notes", map[string]string{"stars": "42", "url": "https://github.com/alice/notes"}),
		}
	default:
		// Unknown handles still return a consistent, honest negative: the
		// platform accounts do not exist in the dataset.
		return []*models.Observation{
			obs("simulation", models.CapUsernameLookup, "username", "github", h, map[string]string{"present": "false"}),
			obs("simulation", models.CapUsernameLookup, "username", "twitter", h, map[string]string{"present": "false"}),
		}
	}
	for _, o := range out {
		o.Timestamp = now
	}
	return out
}
