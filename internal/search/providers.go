package search

import (
	"context"
	"encoding/json"
	"fmt"
	h "hash/fnv"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// Requester is the subset of the shared hardened HTTP client the API provider
// needs. sources.Client satisfies it; the search package defines it locally so
// the provider does not depend on the collector implementation.
type Requester interface {
	Do(ctx context.Context, method, u string, headers http.Header) (*http.Response, []byte, error)
	DoWithBody(ctx context.Context, method, u string, body []byte, headers http.Header) (*http.Response, []byte, error)
}

// MaxResultsPerQuery caps how many hits a single provider response is allowed
// to return, so a chatty endpoint cannot flood the session.
const MaxResultsPerQuery = 30

// SimulationProvider is the offline provider. It returns a deterministic
// dataset derived from an FNV-1a hash of the query, so repeated runs over the
// same target produce byte-identical output with no network access. It uses
// RFC-5761/documented example domains, never real third-party hosts.
type SimulationProvider struct{}

// Name implements Provider.
func (p *SimulationProvider) Name() string { return "simulation" }

// Search implements Provider: deterministic, offline hits for any query.
func (p *SimulationProvider) Search(ctx context.Context, query string) ([]Result, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}
	sample := sampleResults(query, 6)
	out := make([]Result, 0, len(sample))
	for i, r := range sample {
		out = append(out, Result{
			URL:          r.url,
			Title:        fmt.Sprintf("%s — indexed page (%d)", strings.TrimSpace(query), i+1),
			Snippet:      "Offline simulation hit: verify nothing about a simulation; read the report's honesty notes.",
			Provider:     p.Name(),
			Confidence:   models.ConfidencePossible,
			RawReference: "simulation://search",
		})
	}
	return out, nil
}

type simHit struct{ url string }

// sampleResults deterministically picks sample URLs for a query. The selection
// is a pure function of the query, keeping output stable across runs.
func sampleResults(query string, n int) []simHit {
	h := h.New32a()
	_, _ = h.Write([]byte(query))
	seed := h.Sum32()

	base := "example.com" // RFC 2606: never resolved against a real owner
	if seed%2 == 0 {
		base = "example.org"
	}
	paths := []string{
		"",
		"/docs/",
		"/assets/",
		"/blog/",
		"/api/",
		"/login",
	}
	hosts := []string{"www", "www", "mail", "docs", "blog", "dev"}
	out := make([]simHit, 0, n)
	for i := 0; i < n; i++ {
		idx := int(seed+uint32(i)*7) % len(hosts)
		host := hosts[idx]
		if i == 0 {
			host = "www"
		}
		u := "https://" + host + "." + base + paths[i%len(paths)]
		out = append(out, simHit{url: u})
	}
	return out
}

// APIProvider queries a JSON HTTP endpoint. The endpoint contract is:
//
//	GET  {endpoint}?{query_param}={query}        (default)
//	POST {endpoint}   with body {"query": query}
//
// and the response is either a JSON array of result objects or
// {"results": [...]}, where each result supports url/title/snippet/raw.
// The shared hardened client applies timeouts, redirect, body-cap and rate
// limiting; the provider never defeats a challenge and reports it instead.
type APIProvider struct {
	req        Requester
	name       string
	endpoint   string
	token      string
	method     string
	queryParam string
	timeout    time.Duration
}

// APIProviderOptions configures the HTTP API provider.
type APIProviderOptions struct {
	// Requester is the hardened HTTP client.
	Requester Requester
	// Name is the stable provider identifier.
	Name string
	// Endpoint is the base URL queries are issued to.
	Endpoint string
	// Token is set as an Authorization: Bearer header when non-empty.
	Token string
	// Method is GET or POST (default GET).
	Method string
	// QueryParam is the GET query parameter carrying the dork (default
	// "query").
	QueryParam string
	// Timeout guards each request when the Requester allows it (default 15s).
	Timeout time.Duration
}

// NewAPIProvider validates options and returns the provider. Endpoint URL and
// method are strict: an invalid value is an error, not a runtime surprise.
func NewAPIProvider(opts APIProviderOptions) (*APIProvider, error) {
	if opts.Requester == nil {
		return nil, fmt.Errorf("api search provider requires a requester")
	}
	endpoint := strings.TrimSpace(opts.Endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("api search provider requires a non-empty endpoint")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("api search provider endpoint is not a valid HTTP URL: %q", endpoint)
	}
	method := strings.ToUpper(strings.TrimSpace(opts.Method))
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodPost {
		return nil, fmt.Errorf("api search provider method must be GET or POST, got %q", opts.Method)
	}
	qp := strings.TrimSpace(opts.QueryParam)
	if qp == "" {
		qp = "query"
	}
	if method == http.MethodGet {
		if u.User != nil {
			return nil, fmt.Errorf("api search provider endpoint must not embed credentials")
		}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &APIProvider{
		req:        opts.Requester,
		name:       nonEmptyOr(opts.Name, "api"),
		endpoint:   endpoint,
		token:      opts.Token,
		method:     method,
		queryParam: qp,
		timeout:    timeout,
	}, nil
}

// Name implements Provider.
func (p *APIProvider) Name() string { return p.name }

// Search implements Provider.
func (p *APIProvider) Search(ctx context.Context, query string) ([]Result, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	headers := http.Header{
		"Accept":       {"application/json"},
		"Content-Type": {"application/json"},
	}
	if p.token != "" {
		headers.Set("Authorization", "Bearer "+p.token)
	}

	var (
		resp *http.Response
		body []byte
		err  error
	)
	switch p.method {
	case http.MethodPost:
		payload, _ := json.Marshal(map[string]string{p.queryParam: query})
		resp, body, err = p.req.DoWithBody(ctx, p.method, p.endpoint, payload, headers)
	default:
		q := p.queryParam + "=" + url.QueryEscape(query)
		if strings.Contains(p.endpoint, "?") {
			u := p.endpoint + "&" + q
			resp, body, err = p.req.Do(ctx, p.method, u, headers)
		} else {
			u := p.endpoint + "?" + q
			resp, body, err = p.req.Do(ctx, p.method, u, headers)
		}
	}
	if err != nil {
		return nil, err
	}
	if blocked := ClassifyBlocked(resp.StatusCode, string(body)); blocked != nil {
		blocked.Provider = p.Name()
		return nil, blocked
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search provider %q returned status %d", p.Name(), resp.StatusCode)
	}

	hits, err := parseResults(body)
	if err != nil {
		return nil, fmt.Errorf("search provider %q returned unparsable results: %w", p.Name(), err)
	}
	if len(hits) > MaxResultsPerQuery {
		hits = hits[:MaxResultsPerQuery]
	}
	out := make([]Result, 0, len(hits))
	for _, h := range hits {
		h.Provider = p.Name()
		h.RawReference = p.endpoint
		out = append(out, h)
	}
	return out, nil
}

type apiEnvelope struct {
	Results []Result `json:"results"`
}

// parseResults accepts either {"results": [...]} or a bare [...] payload.
func parseResults(body []byte) ([]Result, error) {
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, nil
	}
	var envelope apiEnvelope
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Results != nil {
		return normalizeResults(envelope.Results), nil
	}
	var arr []Result
	if err := json.Unmarshal(body, &arr); err != nil {
		return nil, err
	}
	return normalizeResults(arr), nil
}

// normalizeResults keeps only usable hits (a valid URL host) and sorts them by
// URL for deterministic output.
func normalizeResults(list []Result) []Result {
	out := make([]Result, 0, len(list))
	seen := map[string]bool{}
	for _, r := range list {
		host, ok := ExtractHost(r.URL)
		if !ok {
			continue
		}
		key := host + r.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		r.Title = strings.TrimSpace(r.Title)
		r.Snippet = strings.TrimSpace(r.Snippet)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// ExtractHost returns the lowercased host of an HTTP(S) URL and whether it is
// usable. It is the single entry point for turning a hit URL into a host
// claim, and it rejects anything that is not an http(s) URL with a host.
func ExtractHost(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	return host, true
}

func nonEmptyOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
