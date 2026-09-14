package sources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"

	"github.com/QYVORA/qyvora-nzinga/internal/search"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// maxSearchResults caps the observations a single dork run may return, so a
// chatty provider or a broad category set cannot flood the session.
const maxSearchResults = 400

// maxSearchWorkers bounds concurrent provider queries within one run.
const maxSearchWorkers = 4

// Search performs dork-assisted collection against a configurable search
// provider. It is opt-in (sources.search.enabled=false by default) and is
// never part of a default domain collection pass.
type Search struct {
	cfg    *viper.Viper
	client *Client
	dorks  *search.DorkSet
}

// NewSearch returns the search source bound to a live config reference and the
// shared hardened client. dorks is normally the embedded catalog; tests may
// inject a custom one.
func NewSearch(v *viper.Viper, client *Client, dorks *search.DorkSet) *Search {
	return &Search{cfg: v, client: client, dorks: dorks}
}

// Requester interface: search.Requester is satisfied by delegating to the
// shared client so the API provider inherits its timeouts, redirect guard,
// retries, body caps and rate limiting.

// Do delegates to the shared hardened client.
func (s *Search) Do(ctx context.Context, method, u string, headers http.Header) (*http.Response, []byte, error) {
	if s.client == nil {
		return nil, nil, errors.New("search client is unavailable")
	}
	return s.client.Do(ctx, method, u, headers)
}

// DoWithBody delegates to the shared hardened client.
func (s *Search) DoWithBody(ctx context.Context, method, u string, body []byte, headers http.Header) (*http.Response, []byte, error) {
	if s.client == nil {
		return nil, nil, errors.New("search client is unavailable")
	}
	return s.client.DoWithBody(ctx, method, u, body, headers)
}

// ID implements Source.
func (s *Search) ID() string { return "search" }

// Name implements Source.
func (s *Search) Name() string { return "Search-engine dorking" }

// Capabilities implements Source.
func (s *Search) Capabilities() []models.Capability {
	return []models.Capability{models.CapSearchDork}
}

// Describe implements Source.
func (s *Search) Describe() models.Source {
	return models.Source{
		ID:           "search",
		Name:         "Search-engine dorking",
		Description:  "Curated dork templates executed against a configurable, authorized search provider",
		Category:     models.CategorySearch,
		Capabilities: s.Capabilities(),
		Output:       []models.NodeKind{models.NodeHostname},
		Risk:         models.RiskS1,
		AuthRequired: true,
		Public:       true,
		Targets:      []models.TargetType{models.TargetDomain},
		RateLimit:    "bounded by collection.rate_limit_per_second and sources.search.max_queries",
		Notes:        "Search hits are unverified index snippets, never confirmed facts. Blocked surfaces are reported, never bypassed.",
	}
}

// Collect implements Source.
func (s *Search) Collect(ctx context.Context, t *models.Target) ([]*models.Observation, error) {
	if s.cfg == nil {
		return nil, errors.New("search source requires configuration")
	}
	if t == nil {
		return nil, errors.New("target is nil")
	}
	if t.Type != models.TargetDomain {
		return nil, fmt.Errorf("search dorking supports domain targets, got %q", t.Type)
	}
	provider, err := s.liveProvider()
	if err != nil {
		return nil, err
	}
	return s.run(ctx, provider, t, t.Value)
}

// Simulate implements Source: the offline provider is always available and
// requires no configuration beyond the target itself.
func (s *Search) Simulate(ctx context.Context, t *models.Target) ([]*models.Observation, error) {
	if t == nil {
		return nil, errors.New("target is nil")
	}
	switch t.Type {
	case models.TargetDomain:
		return s.run(ctx, &search.SimulationProvider{}, t, t.Value)
	case models.TargetUsername:
		return s.run(ctx, &search.SimulationProvider{}, t, t.Value)
	default:
		return nil, fmt.Errorf("search dorking supports domain targets, got %q", t.Type)
	}
}

// liveProvider returns the configured online provider, or a clear error when
// search is enabled without a sanctioned provider (search.provider empty).
func (s *Search) liveProvider() (search.Provider, error) {
	name := strings.TrimSpace(s.cfg.GetString("search.provider"))
	switch name {
	case "", "simulation":
		if name == "" {
			return nil, errors.New("search is enabled but no provider is configured (set search.provider or use --sim)")
		}
		return &search.SimulationProvider{}, nil
	case "api":
		endpoint := strings.TrimSpace(s.cfg.GetString("search.endpoint"))
		if endpoint == "" {
			return nil, errors.New("api search provider requires search.endpoint")
		}
		prov, err := search.NewAPIProvider(search.APIProviderOptions{
			Requester:  s,
			Name:       "api",
			Endpoint:   endpoint,
			Token:      strings.TrimSpace(s.cfg.GetString("search.token")),
			Method:     s.cfg.GetString("search.method"),
			QueryParam: s.cfg.GetString("search.query_param"),
			// The shared underlying client is the hardened client; the
			// provider cannot outrun the collection bypass we never attempt.
		})
		if err != nil {
			return nil, err
		}
		return prov, nil
	default:
		return nil, fmt.Errorf("unknown search.provider %q (valid: simulation, api)", name)
	}
}

// run executes the selected queries against a provider and shapes the results
// into observations. Queries run with bounded concurrency; partial failures
// degrade honestly: observations are returned alongside a joined error.
func (s *Search) run(ctx context.Context, provider search.Provider, t *models.Target, target string) ([]*models.Observation, error) {
	queries, err := s.queries(target)
	if err != nil {
		return nil, err
	}

	type outcome struct {
		observations []*models.Observation
		err          error
	}
	results := make([]outcome, len(queries))

	workers := len(queries)
	if workers > maxSearchWorkers {
		workers = maxSearchWorkers
	}
	index := make(chan int, len(queries))
	for i := range queries {
		index <- i
	}
	close(index)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range index {
				obs, err := s.execQuery(ctx, provider, t, queries[i])
				results[i] = outcome{observations: obs, err: err}
			}
		}()
	}
	wg.Wait()

	seen := map[string]bool{}
	var out []*models.Observation
	var errs []error
	failed := 0
	for _, res := range results {
		if res.err != nil {
			failed++
			errs = append(errs, res.err)
			continue
		}
		for _, o := range res.observations {
			key := o.Key + "\x00" + o.Target + "\x00" + o.Value
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, o)
		}
	}
	if len(out) > maxSearchResults {
		out = out[:maxSearchResults]
	}
	sortObservations(out)

	if failed == len(queries) && len(errs) > 0 {
		return out, errors.Join(errs...)
	}
	if len(errs) > 0 {
		return out, fmt.Errorf("search: %d of %d queries failed: %w", failed, len(queries), errors.Join(errs...))
	}
	return out, nil
}

func (s *Search) execQuery(ctx context.Context, provider search.Provider, t *models.Target, q search.Query) ([]*models.Observation, error) {
	hits, err := provider.Search(ctx, q.Query)

	var blocked *search.BlockedError
	if be, ok := search.AsBlocked(err); ok {
		blocked = be
	} else if err != nil {
		return nil, fmt.Errorf("query %q: %w", q.Query, err)
	}

	out := []*models.Observation{s.queryObservation(t, q, provider.Name(), blocked)}
	for _, hit := range hits {
		out = append(out, s.resultObservations(t, q, provider.Name(), hit)...)
	}
	return out, nil
}

// queries derives the rendered query set from configuration.
func (s *Search) queries(target string) ([]search.Query, error) {
	if s.dorks == nil || s.dorks.Count() == 0 {
		return nil, errors.New("search dork catalog is empty")
	}
	categories := splitCategories(s.cfg.GetString("sources.search.categories"))
	maxQueries := s.cfg.GetInt("sources.search.max_queries")
	if maxQueries <= 0 {
		maxQueries = 25
	}
	queries, err := s.dorks.ForTarget(target, categories, maxQueries)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}
	return queries, nil
}

func splitCategories(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (s *Search) queryObservation(t *models.Target, q search.Query, provider string, blocked *search.BlockedError) *models.Observation {
	raw := map[string]string{
		"category": string(q.Category),
		"dork_id":  q.Dork.ID,
		"provider": provider,
	}
	state, confidence := models.StateObserved, models.ConfidenceObserved
	value := q.Query
	claim := "executed search query"
	if blocked != nil {
		state = models.StateInferred
		confidence = models.ConfidencePossible
		raw["blocked"] = blocked.Reason
		raw["blocked_recommended"] = blocked.Recommended
		value = value + " [blocked]"
		claim = "search query blocked by provider; no results claimed"
	}
	return &models.Observation{
		ID:           models.NewID("obs"),
		Source:       "search",
		SourceType:   "web",
		Capability:   models.CapSearchDork,
		Target:       t.Value,
		Key:          "dork_query",
		Value:        value,
		State:        state,
		Confidence:   confidence,
		Claim:        claim,
		Raw:          raw,
		RawReference: providerReference(provider),
		Timestamp:    time.Now().UTC(),
	}
}

func (s *Search) resultObservations(t *models.Target, q search.Query, provider string, hit search.Result) []*models.Observation {
	norm := normalizeResultURL(hit.URL)
	if norm == "" {
		return nil
	}
	now := time.Now().UTC()
	raw := map[string]string{
		"category":          string(q.Category),
		"dork_id":           q.Dork.ID,
		"provider":          provider,
		"confidence":        "unverified",
		"search_present":    "true",
		"result_confidence": string(models.ConfidencePossible),
	}
	if hit.Title != "" {
		raw["title"] = truncateFor(hit.Title, 200)
	}
	if hit.Snippet != "" {
		raw["snippet"] = truncateFor(hit.Snippet, 500)
	}

	out := []*models.Observation{{
		ID:           models.NewID("obs"),
		Source:       "search",
		SourceType:   "web",
		Capability:   models.CapSearchDork,
		Target:       t.Value,
		Key:          "search_result",
		Value:        norm,
		State:        models.StateInferred,
		Confidence:   models.ConfidencePossible,
		Claim:        "search index references a URL for the target",
		Raw:          raw,
		RawReference: providerReference(provider),
		Timestamp:    now,
	}}

	if host, ok := search.ExtractHost(norm); ok && strings.Contains(host, ".") {
		hostRaw := map[string]string{
			"url":        norm,
			"category":   string(q.Category),
			"dork_id":    q.Dork.ID,
			"provider":   provider,
			"confidence": "unverified",
		}
		out = append(out, &models.Observation{
			ID:           models.NewID("obs"),
			Source:       "search",
			SourceType:   "web",
			Capability:   models.CapSearchDork,
			Target:       t.Value,
			Key:          "hostname",
			Value:        host,
			State:        models.StateInferred,
			Confidence:   models.ConfidencePossible,
			Claim:        "hostname referenced by a search index (unverified)",
			Raw:          hostRaw,
			RawReference: providerReference(provider),
			Timestamp:    now,
		})
	}
	return out
}

// normalizeResultURL cleans a hit URL for storage: scheme lowercased, fragment
// and user info dropped, defaults removed. Invalid URLs yield "".
func normalizeResultURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if u.Host == "" {
		return ""
	}
	u.User = nil
	u.Fragment = ""
	u.RawQuery = ""
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if u.Path != "" && u.Path != "/" {
		u.Path = strings.TrimSuffix(u.Path, "/")
	}
	return u.String()
}

func providerReference(provider string) string {
	if provider == "" || provider == "simulation" {
		return "simulation://search"
	}
	return "provider://" + provider
}

func sortObservations(list []*models.Observation) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Key != list[j].Key {
			return list[i].Key < list[j].Key
		}
		return list[i].Value < list[j].Value
	})
}

func truncateFor(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
