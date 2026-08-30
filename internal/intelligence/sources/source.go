// Package sources implements the intelligence collection layer: the Source
// interface, the registry of known collectors, the shared hardened HTTP/TCP
// client, and the collectors themselves.
//
// Collection discipline:
//   - live sources execute only when the target passed the authorization gate;
//   - the offline simulation source is the only source that runs unauthorized;
//   - every collector reports what it could not collect (honest degradation),
//     it never fabricates findings or observations;
//   - results come back as deterministic, deduplicable Observations.
package sources

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/viper"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// ErrUnauthorized is returned when a live source is invoked without an
// authorized target.
var ErrUnauthorized = errors.New("collection requires an authorized target")

// Source is a collector of observations from one public/offline surface.
type Source interface {
	// ID is the stable source identifier, e.g. "crt.sh".
	ID() string
	// Name is the human-readable source name.
	Name() string
	// Capabilities lists what this source can do.
	Capabilities() []models.Capability
	// Collect runs the source against a live, authorized target.
	Collect(ctx context.Context, t *models.Target) ([]*models.Observation, error)
	// Simulate runs the source against the offline deterministic dataset.
	Simulate(ctx context.Context, t *models.Target) ([]*models.Observation, error)
	// Describe returns the static source contract.
	Describe() models.Source
}

// Registry holds the known collectors and routes collection requests.
type Registry struct {
	mu      sync.RWMutex
	sources []Source
	byID    map[string]Source
}

// NewRegistry builds a registry from the given collectors, sorted by ID for
// deterministic listing.
func NewRegistry(sources ...Source) *Registry {
	byID := make(map[string]Source, len(sources))
	sorted := append([]Source(nil), sources...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID() < sorted[j].ID() })
	for _, s := range sorted {
		byID[s.ID()] = s
	}
	return &Registry{sources: sorted, byID: byID}
}

// List returns metadata for every source in deterministic order.
func (r *Registry) List() []models.Source {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]models.Source, 0, len(r.sources))
	for _, s := range r.sources {
		out = append(out, s.Describe())
	}
	return out
}

// Find returns a source by id.
func (r *Registry) Find(id string) (Source, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byID[id]
	return s, ok
}

// Enabled returns the sources whose `sources.<id>.enabled` config flag is
// true, in registry order. Simulation is included when enabled.
func (r *Registry) Enabled(v *viper.Viper) []Source {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Source, 0, len(r.sources))
	for _, s := range r.sources {
		// Source ids may contain dots (e.g. "crt.sh"), which collide with
		// viper's key delimiter, so config keys map dots to underscores
		// (sources.crt_sh.enabled).
		key := "sources." + strings.ReplaceAll(s.ID(), ".", "_") + ".enabled"
		if v.GetBool(key) {
			out = append(out, s)
		}
	}
	return out
}

// Select returns the requested sources by id list, in registry order.
func (r *Registry) Select(ids []string) ([]Source, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("no sources requested")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Source
	seen := map[string]bool{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		s, ok := r.byID[id]
		if !ok {
			return nil, fmt.Errorf("unknown source %q", id)
		}
		seen[id] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid sources requested")
	}
	return out, nil
}

// Run executes the given sources against the target, enforcing the
// authorization gate. The simulation source runs without authorization and
// never touches the network; every other source requires an authorized target.
// Source errors are reported per-source: a single failing source does not
// abort the run (honest degradation).
func (r *Registry) Run(ctx context.Context, v *viper.Viper, t *models.Target, ids []string) ([]*models.Observation, []error) {
	return r.RunMode(ctx, v, t, ids, false)
}

// RunMode executes sources as Run does, with an explicit offline flag. In
// offline mode every source runs its Simulate path and the network is never
// touched; authorization is still required for sources that declare it.
//
// Collection concurrency is bounded by the config key
// collection.source_concurrency (default 1). Sources are always started in
// registry order and results are assembled in the same order, so the emitted
// observation/error sequence is stable regardless of the concurrency setting.
func (r *Registry) RunMode(ctx context.Context, v *viper.Viper, t *models.Target, ids []string, offline bool) ([]*models.Observation, []error) {
	var sources []Source
	if len(ids) > 0 {
		sel, err := r.Select(ids)
		if err != nil {
			return nil, []error{err}
		}
		sources = sel
	} else {
		sources = r.Enabled(v)
	}

	concurrency := 1
	if v != nil {
		if c := v.GetInt("collection.source_concurrency"); c > 0 {
			concurrency = c
		}
	}
	if concurrency > len(sources) {
		concurrency = len(sources)
	}
	if concurrency > 1 {
		return r.runConcurrent(ctx, sources, t, offline, concurrency)
	}

	var observations []*models.Observation
	var errs []error
	for _, s := range sources {
		obs, err := r.runOne(ctx, s, t, offline)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		observations = append(observations, obs...)
	}
	return observations, errs
}

// runOne executes a single source against the target, returning error-wrapped
// failures so callers keep the per-source error message convention.
func (r *Registry) runOne(ctx context.Context, s Source, t *models.Target, offline bool) ([]*models.Observation, error) {
	meta := s.Describe()
	if meta.AuthRequired && (t == nil || !t.Authorized()) {
		return nil, fmt.Errorf("source %q: %w", s.ID(), ErrUnauthorized)
	}
	if offline || meta.ID == "simulation" || !meta.AuthRequired {
		return s.Simulate(ctx, t)
	}
	return s.Collect(ctx, t)
}

// runConcurrent runs sources with a bounded worker pool, preserving registry
// order in the results.
func (r *Registry) runConcurrent(ctx context.Context, sources []Source, t *models.Target, offline bool, workers int) ([]*models.Observation, []error) {
	results := make([]result, len(sources))
	indexByID := make(chan int, len(sources))
	for i := range sources {
		indexByID <- i
	}
	close(indexByID)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range indexByID {
				obs, err := r.runOne(ctx, sources[i], t, offline)
				results[i] = result{obs: obs, err: err}
			}
		}()
	}
	wg.Wait()

	var out []*models.Observation
	var errs []error
	for _, res := range results {
		if res.err != nil {
			errs = append(errs, res.err)
			continue
		}
		out = append(out, res.obs...)
	}
	return out, errs
}

type result struct {
	obs []*models.Observation
	err error
}

// Plan returns a deterministic description of what Run would execute, without
// touching the network. Used by --dry-run.
func (r *Registry) Plan(v *viper.Viper, ids []string, authorized bool) []models.Source {
	var sources []Source
	if len(ids) > 0 {
		sel, err := r.Select(ids)
		if err != nil {
			return nil
		}
		sources = sel
	} else {
		sources = r.Enabled(v)
	}
	out := make([]models.Source, 0, len(sources))
	for _, s := range sources {
		meta := s.Describe()
		if meta.AuthRequired && !authorized {
			continue
		}
		out = append(out, meta)
	}
	return out
}
