package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// crtSh queries the crt.sh certificate transparency log for certificates
// matching a domain. Its principal value is subdomain discovery through
// certificate SANs.
type crtSh struct {
	client *Client
}

// NewCrtSh returns the crt.sh source.
func NewCrtSh(client *Client) *crtSh {
	return &crtSh{client: client}
}

// ID implements Source.
func (c *crtSh) ID() string { return "crt.sh" }

// Name implements Source.
func (c *crtSh) Name() string { return "crt.sh Certificate Transparency" }

// Capabilities implements Source.
func (c *crtSh) Capabilities() []models.Capability {
	return []models.Capability{models.CapCertEnumerate, models.CapSubdomainEnumerate}
}

// Describe implements Source.
func (c *crtSh) Describe() models.Source {
	return models.Source{
		ID:           "crt.sh",
		Name:         "crt.sh Certificate Transparency",
		Description:  "Certificate transparency log lookup enriching SAN-side subdomains and emails",
		Category:     models.CategoryCertificate,
		Capabilities: c.Capabilities(),
		Output:       []models.NodeKind{models.NodeCertificate, models.NodeHostname, models.NodeEmail},
		Risk:         models.RiskS1,
		AuthRequired: true,
		Public:       true,
		Targets:      []models.TargetType{models.TargetDomain, models.TargetInfrastructure},
		RateLimit:    "shared",
	}
}

type crtEntry struct {
	CommonName string    `json:"common_name"`
	NameValue  string    `json:"name_value"`
	IssuerName string    `json:"issuer_name"`
	Serial     string    `json:"serial_number"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
}

// Collect implements Source: it queries https://crt.sh for the domain and
// emits hostname observations for every certificate SAN.
func (c *crtSh) Collect(ctx context.Context, t *models.Target) ([]*models.Observation, error) {
	if t == nil {
		return nil, fmt.Errorf("target is nil")
	}
	domain := normalizeHost(t.Value)
	if domain == "" {
		return nil, fmt.Errorf("no domain in target %q", t.DisplayName())
	}
	if c.client == nil {
		return nil, fmt.Errorf("crt.sh client is unavailable (see logs)")
	}

	u := "https://crt.sh/?q=%25." + domain + "&output=json"
	headers := http.Header{"Accept": {"application/json"}}
	resp, body, err := c.client.Do(ctx, http.MethodGet, u, headers)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("crt.sh rate limited (429): try again later or lower your collection rate")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parsing crt.sh response: %w", err)
	}

	var out []*models.Observation
	now := time.Now().UTC()
	seen := map[string]bool{}

	emit := func(key, target, value string, raw map[string]string, observedAt time.Time) {
		dedupe := key + "\x00" + target + "\x00" + value
		if seen[dedupe] {
			return
		}
		seen[dedupe] = true
		o := &models.Observation{
			ID:           models.NewID("obs"),
			Source:       "crt.sh",
			SourceType:   "cert", // certificate transparency taxonomy
			Capability:   models.CapCertEnumerate,
			Target:       target,
			Key:          key,
			Value:        value,
			State:        models.StateObserved,
			Confidence:   models.ConfidenceObserved,
			Raw:          raw,
			RawReference: "https://crt.sh/?q=" + domain,
			CollectedAt:  now,
			Timestamp:    now,
		}
		if !observedAt.IsZero() {
			o.ObservedAt = observedAt
		}
		out = append(out, o)
	}

	for _, e := range entries {
		raw := map[string]string{}
		if e.IssuerName != "" {
			raw["issuer"] = e.IssuerName
		}
		if e.Serial != "" {
			raw["serial"] = e.Serial
		}
		if !e.NotBefore.IsZero() {
			raw["not_before"] = e.NotBefore.Format(time.RFC3339)
		}
		if !e.NotAfter.IsZero() {
			raw["not_after"] = e.NotAfter.Format(time.RFC3339)
		}
		emit("cert", domain, e.CommonName, raw, e.NotBefore)

		names := append([]string{e.CommonName}, strings.Split(e.NameValue, "\n")...)
		for _, name := range names {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" {
				continue
			}
			if strings.Contains(name, "@") {
				emit("email", domain, name, raw, e.NotBefore)
				continue
			}
			emit("hostname", domain, name, raw, e.NotBefore)
		}
	}
	return out, nil
}

// Simulate implements Source: deterministic offline data for example.com.
func (c *crtSh) Simulate(ctx context.Context, t *models.Target) ([]*models.Observation, error) {
	if t == nil {
		return nil, fmt.Errorf("target is nil")
	}
	switch t.Type {
	case models.TargetDomain, models.TargetInfrastructure:
		d := normalizeHost(t.Value)
		if !isExampleDomain(d) {
			return nil, fmt.Errorf("the offline dataset covers example.com, example.net and example.org only")
		}
		return simulatedCertObservations(d), nil
	default:
		return nil, nil
	}
}

func simulatedCertObservations(domain string) []*models.Observation {
	var out []*models.Observation
	now := time.Now().UTC()
	emit := func(key, target, value string, raw map[string]string) {
		o := &models.Observation{
			ID:           models.NewID("obs"),
			Source:       "crt.sh",
			SourceType:   "cert",
			Capability:   models.CapCertEnumerate,
			Target:       target,
			Key:          key,
			Value:        value,
			State:        models.StateObserved,
			Confidence:   models.ConfidenceObserved,
			Raw:          raw,
			RawReference: "https://crt.sh/?q=" + domain,
			CollectedAt:  now,
			Timestamp:    now,
		}
		if raw != nil {
			if nb, err := time.Parse(time.RFC3339, raw["not_before"]); err == nil {
				o.ObservedAt = nb
			}
		}
		out = append(out, o)
	}

	// Cert #1 for the apex plus www and staging (staging not in the local
	// wordlist — crt.sh discovered it, which is the honest OSINT point).
	emit("cert", domain, domain, map[string]string{"issuer": "Example CA / G1", "serial": "0FA0C0DE", "not_before": "2024-01-15T00:00:00Z", "not_after": "2025-01-15T00:00:00Z"})
	emit("hostname", domain, "www."+domain, nil)
	emit("hostname", domain, "staging."+domain, nil)

	emit("cert", domain, "*."+domain, map[string]string{"issuer": "Example CA / G1", "serial": "0FA0C0DF", "not_before": "2024-02-01T00:00:00Z", "not_after": "2025-02-01T00:00:00Z"})
	emit("hostname", domain, "api."+domain, nil)
	emit("hostname", domain, "cdn."+domain, nil)
	emit("hostname", domain, "mail."+domain, nil)

	emit("cert", domain, domain, map[string]string{"issuer": "Other CA / G2", "serial": "0FA0C0E0", "not_before": "2023-05-01T00:00:00Z", "not_after": "2024-05-01T00:00:00Z"})

	if domain == "example.com" {
		emit("email", domain, "admin@"+domain, map[string]string{"issuer": "Example CA / G1", "serial": "0FA0C0DE", "not_before": "2024-01-15T00:00:00Z"})
		// A second domain sharing hosting appears in example.com's SANs;
		// correlation will link example.com and example.net.
		emit("hostname", domain, "mail.example.net", nil)
	}
	// The sibling domain's certificates reference mail.example.com back, so an
	// assessment of example.net independently surfaces the same overlap.
	if domain == "example.net" {
		emit("hostname", domain, "mail.example.com", nil)
	}
	return out
}
