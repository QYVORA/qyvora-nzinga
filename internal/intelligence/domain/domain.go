// Package domain orchestrates collection for domain and infrastructure
// targets. The order matters and is fixed: certificate-log subdomain
// discovery first, then a DNS resolution pass over everything discovered,
// then registry WHOIS metadata.
package domain

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/viper"

	"github.com/QYVORA/qyvora-nzinga/internal/intelligence/sources"
	"github.com/QYVORA/qyvora-nzinga/internal/logger"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// maxResolvable caps how many discovered hostnames feed the DNS resolution
// pass, so a certificate log with thousands of SANs cannot stall the run.
const maxResolvable = 50

// Collector runs the fixed source order for a domain/infrastructure target.
type Collector struct {
	Registry *sources.Registry
	Config   *viper.Viper
	Log      *logger.Logger
}

// Collect executes the pipeline of sources and returns the combined
// observations. In offline mode the simulation dataset is used and the DNS
// pass is skipped (the dataset already carries its resolution results).
func (c *Collector) Collect(ctx context.Context, t *models.Target, offline bool) ([]*models.Observation, []error) {
	if t == nil {
		return nil, []error{fmt.Errorf("target is nil")}
	}

	var observations []*models.Observation
	var errs []error

	if offline {
		obs, runErrs := c.Registry.RunMode(ctx, c.Config, t, nil, true)
		return obs, runErrs
	}

	// Stage 1: certificate transparency -> subdomain/hostname discovery.
	obs, runErrs := c.Registry.Run(ctx, c.Config, t, []string{"crt.sh"})
	observations = append(observations, obs...)
	errs = append(errs, runErrs...)

	// Stage 2: resolve every discovered hostname via DNS. Failures degrade
	// honestly: the hostname observation still stands, only its A/AAAA edges
	// may be missing.
	hosts := discoveredHostnames(observations)
	if len(hosts) > maxResolvable {
		hosts = hosts[:maxResolvable]
	}
	if dnsSrc, ok := c.Registry.Find("dns"); ok {
		dns, ok := dnsSrc.(*sources.DNS)
		if ok {
			for _, h := range hosts {
				resolved, err := dns.Resolve(ctx, h)
				if err != nil {
					errs = append(errs, fmt.Errorf("dns %q: %w", h, err))
					continue
				}
				observations = append(observations, resolved...)
			}
		}
	}

	// Stage 3: whois metadata for the apex domain.
	obs, runErrs = c.Registry.Run(ctx, c.Config, t, []string{"whois"})
	observations = append(observations, obs...)
	errs = append(errs, runErrs...)

	return observations, errs
}

func discoveredHostnames(observations []*models.Observation) []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range observations {
		if o == nil || o.Key != "hostname" {
			continue
		}
		v := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(o.Value), "."))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
