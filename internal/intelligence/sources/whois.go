package sources

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// Whois performs port-43 WHOIS lookups for domains. It uses the IANA
// referral system to find the authoritative registry server for each TLD and
// then asks that server for the record. Parsing is best-effort: fields that
// vary between registries are collected by a small key vocabulary and
// everything else is ignored.
type Whois struct {
	port string
}

// NewWhois returns the WHOIS source.
func NewWhois(port int) *Whois {
	if port <= 0 {
		port = 43
	}
	return &Whois{port: fmt.Sprintf("%d", port)}
}

// ID implements Source.
func (w *Whois) ID() string { return "whois" }

// Name implements Source.
func (w *Whois) Name() string { return "WHOIS registry" }

// Capabilities implements Source.
func (w *Whois) Capabilities() []models.Capability {
	return []models.Capability{models.CapWhoisLookup}
}

// Describe implements Source.
func (w *Whois) Describe() models.Source {
	return models.Source{
		ID:           "whois",
		Name:         "WHOIS registry",
		Description:  "IANA-referred port-43 WHOIS for a domain's registrant metadata",
		Category:     models.CategoryRegistry,
		Capabilities: w.Capabilities(),
		Output:       []models.NodeKind{models.NodeOrganization, models.NodeEmail},
		Risk:         models.RiskS1,
		AuthRequired: true,
		Public:       true,
		Targets:      []models.TargetType{models.TargetDomain},
		RateLimit:    "registry",
	}
}

// Collect implements Source.
func (w *Whois) Collect(ctx context.Context, t *models.Target) ([]*models.Observation, error) {
	if t == nil {
		return nil, fmt.Errorf("target is nil")
	}
	if t.Type != models.TargetDomain {
		return nil, nil
	}
	domain := normalizeHost(t.Value)
	if domain == "" {
		return nil, fmt.Errorf("no domain in target %q", t.DisplayName())
	}

	server := "whois.iana.org"
	query := tldOf(domain)
	if info, err := w.query(ctx, server, query); err == nil {
		if ref, ok := info["whois"]; ok && !strings.HasSuffix(ref, server) {
			server = ref
		}
	} else {
		// IANA unreachable: still attempt the domain against iana (rarely
		// useful) then give up honestly.
		return nil, fmt.Errorf("whois: %w", err)
	}

	info, err := w.query(ctx, server, domain)
	if err != nil {
		return nil, err
	}

	var out []*models.Observation
	now := time.Now().UTC()
	emit := func(key, value string, raw map[string]string) {
		out = append(out, &models.Observation{
			ID:         models.NewID("obs"),
			Source:     "whois",
			Capability: models.CapWhoisLookup,
			Target:     domain,
			Key:        key,
			Value:      value,
			State:      models.StateObserved,
			Confidence: models.ConfidenceObserved,
			Raw:        raw,
			Timestamp:  now,
		})
	}

	raw := map[string]string{"server": server}
	for _, k := range []string{"Registrar", "Creation Date", "Registry Expiry Date"} {
		if v := info[k]; v != "" {
			raw[strings.ToLower(strings.ReplaceAll(k, " ", "_"))] = v
		}
	}
	if org := first(info, "Registrant Organization", "registrant_org", "org"); org != "" {
		emit("registrant", org, raw)
	}
	if email := first(info, "Registrant Email", "abuse-mailbox", "Registrar Abuse Contact Email"); email != "" {
		emit("email", strings.ToLower(strings.TrimSpace(email)), raw)
	}
	for i := 1; i < 4; i++ {
		if ns := info[fmt.Sprintf("Name Server%d", i)]; ns != "" {
			emit("nameserver", strings.TrimSuffix(strings.TrimSpace(ns), "."), raw)
		}
	}
	return out, nil
}

// query performs one port-43 query and parses "key: value" lines.
func (w *Whois) query(ctx context.Context, server, query string) (map[string]string, error) {
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(server, w.port))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	}
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return nil, err
	}

	out := make(map[string]string)
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		if v == "" {
			continue
		}
		if _, exists := out[k]; !exists {
			out[k] = v
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func tldOf(domain string) string {
	idx := strings.LastIndex(domain, ".")
	if idx < 0 || idx == len(domain)-1 {
		return domain
	}
	return domain[idx+1:]
}

func first(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(m[k]); v != "" {
			return v
		}
	}
	return ""
}

// Simulate implements Source: mirrors the offline dataset.
func (w *Whois) Simulate(ctx context.Context, t *models.Target) ([]*models.Observation, error) {
	if t == nil {
		return nil, fmt.Errorf("target is nil")
	}
	if t.Type != models.TargetDomain {
		return nil, nil
	}
	d := normalizeHost(t.Value)
	if !isExampleDomain(d) {
		return nil, fmt.Errorf("the offline dataset covers example.com, example.net and example.org only")
	}
	return simulatedWhoisObservations(d), nil
}
