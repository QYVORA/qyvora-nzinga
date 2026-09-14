package sources

import (
	"context"
	"testing"

	"github.com/spf13/viper"

	"github.com/QYVORA/qyvora-nzinga/internal/search"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

func newTestSearch(t *testing.T) *Search {
	t.Helper()
	dorks, err := search.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	return NewSearch(viper.New(), nil, dorks)
}

func TestSearchSimulateDomain(t *testing.T) {
	s := newTestSearch(t)
	s.cfg.Set("sources.search.max_queries", 10)
	tgt := &models.Target{Type: models.TargetDomain, Value: "example.com"}

	obs, err := s.Simulate(context.Background(), tgt)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if len(obs) == 0 {
		t.Fatal("simulation produced no observations")
	}
	var queries, results, hosts int
	for _, o := range obs {
		switch o.Key {
		case "dork_query":
			queries++
		case "search_result":
			results++
		case "hostname":
			hosts++
			if o.State != models.StateInferred || o.Confidence != models.ConfidencePossible {
				t.Fatalf("search hostname must be inferred/possible, got %s/%s", o.State, o.Confidence)
			}
		}
		if o.Capability != models.CapSearchDork {
			t.Fatalf("wrong capability %q", o.Capability)
		}
	}
	if queries == 0 || results == 0 {
		t.Fatalf("expected dork_query+search_result observations, got q=%d r=%d", queries, results)
	}
}

func TestSearchSimulateUnsupportedType(t *testing.T) {
	s := newTestSearch(t)
	tgt := &models.Target{Type: models.TargetIP, Value: "192.0.2.1"}
	if _, err := s.Simulate(context.Background(), tgt); err == nil {
		t.Fatal("simulate for IP target should error")
	}
}

func TestSearchCollectWithoutProvider(t *testing.T) {
	s := newTestSearch(t)
	tgt := &models.Target{Type: models.TargetDomain, Value: "example.com"}
	if _, err := s.Collect(context.Background(), tgt); err == nil {
		t.Fatal("collect without a provider should error honestly")
	}
}

func TestSearchCollectWithSimulationProvider(t *testing.T) {
	s := newTestSearch(t)
	s.cfg.Set("sources.search.max_queries", 2)
	s.cfg.Set("search.provider", "simulation")
	tgt := &models.Target{Type: models.TargetDomain, Value: "example.com"}
	obs, err := s.Collect(context.Background(), tgt)
	if err != nil {
		t.Fatalf("Collect with simulation provider: %v", err)
	}
	if len(obs) == 0 {
		t.Fatal("expected observations")
	}
}

func TestSearchDescribe(t *testing.T) {
	s := newTestSearch(t)
	d := s.Describe()
	if d.ID != "search" || d.Risk != models.RiskS1 || !d.AuthRequired || !d.Public {
		t.Fatalf("unexpected contract: %+v", d)
	}
	if d.Category != models.CategorySearch {
		t.Fatalf("unexpected category %q", d.Category)
	}
	if len(d.Capabilities) != 1 || d.Capabilities[0] != models.CapSearchDork {
		t.Fatalf("unexpected capabilities %v", d.Capabilities)
	}
}

func TestSearchDedupAcrossQueries(t *testing.T) {
	// Two queries whose simulation dataset can overlap must still yield a
	// deduplicated observation set (no duplicate key/target/value).
	s := newTestSearch(t)
	s.cfg.Set("sources.search.max_queries", 0) // use all; exercises shared dedup
	tgt := &models.Target{Type: models.TargetDomain, Value: "example.com"}
	obs, err := s.Simulate(context.Background(), tgt)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	seen := map[string]bool{}
	for _, o := range obs {
		key := o.Key + "\x00" + o.Target + "\x00" + o.Value
		if seen[key] {
			t.Fatalf("duplicate observation %s=%s", o.Key, o.Value)
		}
		seen[key] = true
	}
}
