package sources

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// DNS resolves records for domains and hostnames using the system resolver.
// It never performs brute-force enumeration; it only resolves names the rest
// of the pipeline has already discovered.
type DNS struct{}

// NewDNS returns the DNS source.
func NewDNS() *DNS { return &DNS{} }

// ID implements Source.
func (d *DNS) ID() string { return "dns" }

// Name implements Source.
func (d *DNS) Name() string { return "DNS" }

// Capabilities implements Source.
func (d *DNS) Capabilities() []models.Capability {
	return []models.Capability{models.CapDNSResolve}
}

// Describe implements Source.
func (d *DNS) Describe() models.Source {
	return models.Source{
		ID:           "dns",
		Name:         "DNS",
		Description:  "Resolves A/AAAA/CNAME/NS/MX/TXT records via the system resolver",
		Category:     models.CategoryDNS,
		Capabilities: d.Capabilities(),
		Output:       []models.NodeKind{models.NodeHostname, models.NodeIP},
		Risk:         models.RiskS1,
		AuthRequired: true,
		Public:       true,
		Targets:      []models.TargetType{models.TargetDomain, models.TargetInfrastructure},
		RateLimit:    "sysconf",
	}
}

// Collect implements Source. For a domain it resolves the apex and the
// conventional www host; orchestrators call Resolve for every hostname the
// pipeline discovers.
func (d *DNS) Collect(ctx context.Context, t *models.Target) ([]*models.Observation, error) {
	if t == nil {
		return nil, fmt.Errorf("target is nil")
	}
	switch t.Type {
	case models.TargetDomain, models.TargetInfrastructure:
		name := normalizeHost(t.Value)
		if name == "" {
			return nil, fmt.Errorf("no resolvable host in target %q", t.DisplayName())
		}
		return d.resolveAll(ctx, name)
	default:
		// dns.source has nothing to say for person/org/username/ip targets.
		return nil, nil
	}
}

// Simulate implements Source: the offline DNS dataset mirrors the simulation
// source's resolution results for the documented example domains. Unknown
// domains resolve to nothing (no fabricated records).
func (d *DNS) Simulate(ctx context.Context, t *models.Target) ([]*models.Observation, error) {
	if t == nil {
		return nil, fmt.Errorf("target is nil")
	}
	switch t.Type {
	case models.TargetDomain, models.TargetInfrastructure:
		name := normalizeHost(t.Value)
		if name == "" {
			return nil, fmt.Errorf("no resolvable host in target %q", t.DisplayName())
		}
		if isExampleDomain(name) {
			return simulatedDNSObservations(name), nil
		}
		return nil, nil
	default:
		return nil, nil
	}
}

func (d *DNS) resolveAll(ctx context.Context, name string) ([]*models.Observation, error) {
	obs, err := d.Resolve(ctx, name)
	if err != nil {
		return nil, err
	}
	if name != "www."+name {
		wwwObs, err := d.Resolve(ctx, "www."+name)
		if err == nil {
			obs = append(obs, wwwObs...)
		}
	}
	return obs, nil
}

// Resolve returns observations for a single hostname: an entity observation
// plus one observation per record type that resolved.
func (d *DNS) Resolve(ctx context.Context, host string) ([]*models.Observation, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("invalid host")
	}

	var out []*models.Observation
	now := time.Now().UTC()
	add := func(key, value string) {
		out = append(out, &models.Observation{
			ID:         models.NewID("obs"),
			Source:     "dns",
			Capability: models.CapDNSResolve,
			Target:     host,
			Key:        key,
			Value:      value,
			State:      models.StateObserved,
			Confidence: models.ConfidenceObserved,
			Timestamp:  now,
		})
	}

	add("hostname", host)

	r := &net.Resolver{PreferGo: preferGoDNS()}

	if ips, err := r.LookupNetIP(ctx, "ip4", host); err == nil {
		for _, ip := range ips {
			add("a", ip.String())
		}
	}
	if ips, err := r.LookupNetIP(ctx, "ip6", host); err == nil {
		for _, ip := range ips {
			add("aaaa", ip.String())
		}
	}
	if cname, err := r.LookupCNAME(ctx, host); err == nil && cname != "" {
		add("cname", strings.TrimSuffix(cname, "."))
	}
	if ns, err := r.LookupNS(ctx, host); err == nil {
		for _, n := range ns {
			add("nameserver", strings.TrimSuffix(n.Host, "."))
		}
	}
	if mx, err := r.LookupMX(ctx, host); err == nil {
		for _, m := range mx {
			add("mx", strings.TrimSuffix(m.Host, "."))
		}
	}
	if txt, err := r.LookupTXT(ctx, host); err == nil {
		for _, t := range txt {
			add("txt", t)
		}
	}
	return out, nil
}

// preferGoDNS uses a small UDP fallback guard: with a nil resolver the
// default resolver is used; PreferGo avoids racing libc when a host file is
// present. A custom DNS-over-TCP fallback is out of scope.
func preferGoDNS() bool { return true }

func normalizeHost(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return ""
	}
	if u := strings.Index(s, "://"); u >= 0 {
		s = s[u+3:]
	}
	if idx := strings.Index(s, "/"); idx >= 0 {
		s = s[:idx]
	}
	return s
}
