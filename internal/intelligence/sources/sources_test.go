package sources

import (
	"testing"

	"github.com/QYVORA/qyvora-nzinga/internal/config"
)

func TestEnabledResolvesDotIDsToUnderscoreKeys(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	reg := NewRegistry(
		NewCrtSh(nil),
		NewDNS(),
		NewWhois(43),
		NewGitHub(nil, ""),
		NewSimulation(),
	)
	enabled := reg.Enabled(cfg)
	ids := make(map[string]bool, len(enabled))
	for _, s := range enabled {
		ids[s.ID()] = true
	}
	if !ids["crt.sh"] {
		t.Fatalf("crt.sh must be enabled by default (config key sources.crt_sh.enabled): got %v", ids)
	}
	for _, id := range []string{"dns", "whois", "github", "simulation"} {
		if !ids[id] {
			t.Fatalf("source %q expected enabled by default, got %v", id, ids)
		}
	}
}

func TestEnabledDisablesSourceByConfig(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Set("sources.whois.enabled", false)
	reg := NewRegistry(NewWhois(43))
	if got := reg.Enabled(cfg); len(got) != 0 {
		t.Fatalf("whois should be disabled, got %d sources", len(got))
	}
}

func TestRegistryListOrderIsDeterministic(t *testing.T) {
	reg := NewRegistry(
		NewGitHub(nil, ""),
		NewSimulation(),
		NewCrtSh(nil),
		NewDNS(),
		NewWhois(43),
	)
	meta := reg.List()
	prev := ""
	for _, m := range meta {
		if m.ID < prev {
			t.Fatalf("registry list out of order: %q after %q", m.ID, prev)
		}
		prev = m.ID
	}
}
