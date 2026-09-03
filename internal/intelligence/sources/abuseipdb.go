package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// AbuseIPDB queries the AbuseIPDB v2 check API for an IP address's abuse
// reputation. It requires a configured API key (read-only; no writes to the
// service). The score is surfaced as observations with provenance so it feeds
// evidence and comparisons without fabricating an assessment.
type AbuseIPDB struct {
	client *Client
	key    string
}

// NewAbuseIPDB returns the AbuseIPDB reputation source.
func NewAbuseIPDB(client *Client, key string) *AbuseIPDB {
	return &AbuseIPDB{client: client, key: key}
}

// ID implements Source.
func (a *AbuseIPDB) ID() string { return "abuseipdb" }

// Name implements Source.
func (a *AbuseIPDB) Name() string { return "AbuseIPDB reputation" }

// Capabilities implements Source.
func (a *AbuseIPDB) Capabilities() []models.Capability {
	return []models.Capability{models.CapIPLookup}
}

// Describe implements Source.
func (a *AbuseIPDB) Describe() models.Source {
	return models.Source{
		ID:           "abuseipdb",
		Name:         "AbuseIPDB reputation",
		Description:  "Abuse IP reputation score, report count and usage type for an IP address via api.abuseipdb.com",
		Category:     models.CategoryNetwork,
		Capabilities: a.Capabilities(),
		Output:       []models.NodeKind{models.NodeIP},
		Risk:         models.RiskS2,
		AuthRequired: true,
		Public:       true,
		Targets:      []models.TargetType{models.TargetIP},
		RateLimit:    "API key",
		Notes:        "Read-only reputation lookup; a missing key makes live collection fail honestly.",
	}
}

// abuseCheckData mirrors the subset of the v2 check response this source uses.
type abuseCheckData struct {
	IPAddress            string   `json:"ipAddress"`
	IPVersion            int      `json:"ipVersion"`
	IsWhitelisted        bool     `json:"isWhitelisted"`
	AbuseConfidenceScore int      `json:"abuseConfidenceScore"`
	CountryCode          string   `json:"countryCode"`
	UsageType            string   `json:"usageType"`
	ISP                  string   `json:"isp"`
	Domain               string   `json:"domain"`
	Hostnames            []string `json:"hostnames"`
	TotalReports         int      `json:"totalReports"`
	NumDistinctUsers     int      `json:"numDistinctUsers"`
	LastReportedAt       string   `json:"lastReportedAt"`
}

// abuseCheck is the full envelope parsed from the API response.
type abuseCheck struct {
	Data   abuseCheckData `json:"data"`
	Errors []struct {
		Detail string `json:"detail"`
	} `json:"errors"`
}

// Collect implements Source.
func (a *AbuseIPDB) Collect(ctx context.Context, t *models.Target) ([]*models.Observation, error) {
	if t == nil {
		return nil, fmt.Errorf("target is nil")
	}
	if a.client == nil {
		return nil, fmt.Errorf("abuseipdb client is unavailable (see logs)")
	}
	if t.Type != models.TargetIP {
		return nil, nil
	}
	ip := strings.TrimSpace(t.Value)
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("invalid IP address %q", ip)
	}
	if strings.TrimSpace(a.key) == "" {
		return nil, fmt.Errorf("abuseipdb requires an API key (configure sources.abuseipdb.token)")
	}

	hdr := http.Header{
		"Accept": {"application/json"},
		"Key":    {strings.TrimSpace(a.key)},
	}
	resp, body, err := a.client.Do(ctx, http.MethodGet, "https://api.abuseipdb.com/api/v2/check?ipAddress="+ip+"&maxAgeInDays=90", hdr)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abuseipdb returned status %d for %s", resp.StatusCode, ip)
	}
	var check abuseCheck
	if err := json.Unmarshal(body, &check); err != nil {
		return nil, fmt.Errorf("abuseipdb: decoding response: %w", err)
	}
	if len(check.Errors) > 0 {
		return nil, fmt.Errorf("abuseipdb: %s", check.Errors[0].Detail)
	}
	return abuseObservations(ip, &check.Data), nil
}

// Simulate implements Source: mirrors the offline dataset for the recognized
// demo address, and honestly reports no data otherwise.
func (a *AbuseIPDB) Simulate(ctx context.Context, t *models.Target) ([]*models.Observation, error) {
	if t == nil {
		return nil, fmt.Errorf("target is nil")
	}
	if t.Type != models.TargetIP {
		return nil, nil
	}
	ip := strings.TrimSpace(t.Value)
	if ip != "203.0.113.10" {
		return nil, nil
	}
	return abuseObservations(ip, &abuseCheckData{
		IPAddress:            ip,
		IPVersion:            4,
		AbuseConfidenceScore: 15,
		CountryCode:          "US",
		UsageType:            "Data Center/Web Hosting/Transit",
		ISP:                  "Example Hosting",
		Domain:               "example.net",
		TotalReports:         3,
		NumDistinctUsers:     2,
	}), nil
}

// abuseObservations converts a check result into reputation observations. The
// keys deliberately fall outside the normalization vocabulary so they remain
// observations with evidence (they are not typed into graph entities).
func abuseObservations(ip string, d *abuseCheckData) []*models.Observation {
	now := time.Now().UTC()
	out := []*models.Observation{
		abuseObs(ip, "ip.abuse.score", strconv.Itoa(d.AbuseConfidenceScore), now),
		abuseObs(ip, "ip.abuse.total_reports", strconv.Itoa(d.TotalReports), now),
	}
	if d.UsageType != "" {
		out = append(out, abuseObs(ip, "ip.abuse.usage", d.UsageType, now))
	}
	if d.ISP != "" {
		out = append(out, abuseObs(ip, "ip.abuse.isp", d.ISP, now))
	}
	for _, o := range out {
		o.Raw = map[string]string{"country": d.CountryCode, "whitelisted": boolStr(d.IsWhitelisted)}
	}
	return out
}

func abuseObs(ip, key, value string, now time.Time) *models.Observation {
	return &models.Observation{
		ID:         models.NewID("obs"),
		Source:     "abuseipdb",
		Capability: models.CapIPLookup,
		Target:     ip,
		Key:        key,
		Value:      value,
		State:      models.StateObserved,
		Confidence: models.ConfidenceObserved,
		Raw:        map[string]string{"source": "api.abuseipdb.com/v2/check"},
		Timestamp:  now,
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
