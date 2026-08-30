// Package builtin contains the shipped nzinga rules (OSINT-001..004). Each
// rule is deliberately narrow: it only fires on evidence the pipeline actually
// collected, and each fires deterministically. There are no throwaway "stub"
// rules.
package builtin

import (
	"github.com/QYVORA/qyvora-nzinga/internal/rules"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// All returns every builtin rule in documentation order.
func All() []*rules.Rule {
	return []*rules.Rule{
		usernameReuse(),
		infrastructureOverlap(),
		exposedPIIEmail(),
		dnsWildcard(),
	}
}

func usernameReuse() *rules.Rule {
	return &rules.Rule{
		ID:          "OSINT-001",
		Name:        "Username reuse across sources",
		Category:    "identity-reuse",
		Description: "A username is observed on two or more independent platforms, indicating probable identity linkage across those services.",
		Severity:    models.SeverityInformational,
		Confidence:  models.ConfidenceProbable,
		Remediation: "No remediation applies: this is an identity-consistency observation. Treat as attribution context, not as a compromise.",
		ObjectTypes: []string{"username"},
		Detect: func(ctx *rules.Context) []*models.Finding {
			var findings []*models.Finding
			for _, u := range ctx.Usernames {
				if u == nil {
					continue
				}
				platforms := distinctPlatforms(u.Platforms)
				if len(platforms) < 2 {
					continue
				}
				obs := observationsFor(ctx, "username", u.Handle)
				attrib := map[string]string{"platforms": joinList(platforms), "sources": sourceList(obs)}
				findings = append(findings, &models.Finding{
					Title:       "Username " + u.Handle + " reused across multiple platforms",
					Category:    "identity-reuse",
					Description: "Handle " + u.Handle + " was observed on " + joinList(platforms) + ", which is consistent with a single person controlling all of those accounts.",
					Severity:    models.SeverityInformational,
					Confidence:  models.ConfidenceProbable,
					Status:      models.StatusDetected,
					State:       models.StateObserved,
					Objects:     []string{u.ID},
					Evidence:    evidenceFrom(obs),
					Attributes:  attrib,
				})
			}
			return findings
		},
	}
}

func infrastructureOverlap() *rules.Rule {
	return &rules.Rule{
		ID:          "OSINT-002",
		Name:        "Infrastructure overlap across domains",
		Category:    "infrastructure-overlap",
		Description: "Two or more distinct domains resolve to the same hosting (shared IP/ASN), indicating common administration or a shared provider surface.",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfidenceProbable,
		Remediation: "Treat co-located domains as related infrastructure when scoping or monitoring; shared IPs can mask separate estates.",
		ObjectTypes: []string{"domain", "ip"},
		Detect: func(ctx *rules.Context) []*models.Finding {
			// Map each IP to the set of distinct domains whose hostnames
			// resolve to it (via the hostname->domain and hostname->ip edges).
			ipDomains := map[string]map[string]bool{}
			domByID := map[string]string{}
			for _, d := range ctx.Domains {
				if d != nil {
					domByID[d.ID] = d.Name
				}
			}
			ipAddrByID := map[string]string{}
			for _, ip := range ctx.IPs {
				if ip != nil {
					ipAddrByID[ip.ID] = ip.Address
				}
			}
			hnDomainID := map[string]string{} // hostname ID -> domain ID
			for _, e := range ctx.Edges {
				if e == nil {
					continue
				}
				if e.Type == models.RelOwes {
					if _, ok := domByID[e.To]; ok {
						hnDomainID[e.From] = e.To
					}
				}
			}
			for _, e := range ctx.Edges {
				if e == nil || e.Type != models.RelResolvesTo {
					continue
				}
				domID, ok := hnDomainID[e.From]
				if !ok {
					continue
				}
				domName, ok := domByID[domID]
				if !ok {
					continue
				}
				if ipDomains[e.To] == nil {
					ipDomains[e.To] = map[string]bool{}
				}
				ipDomains[e.To][domName] = true
			}

			var findings []*models.Finding
			for ipID, doms := range ipDomains {
				ip := ipAddrByID[ipID]
				if ip == "" {
					continue
				}
				var names []string
				for d := range doms {
					names = append(names, d)
				}
				sortStrings(names)
				if len(names) < 2 {
					continue
				}
				obs := observationsForKey(ctx, "a", ip)
				findings = append(findings, &models.Finding{
					Title:       "Infrastructure overlap: " + joinList(names) + " share " + ip,
					Category:    "infrastructure-overlap",
					Description: "Hostnames of " + joinList(names) + " resolve to the same address " + ip + ", indicating shared hosting or administration.",
					Severity:    models.SeverityMedium,
					Confidence:  models.ConfidenceProbable,
					Status:      models.StatusDetected,
					State:       models.StateObserved,
					Objects:     []string{ip},
					Evidence:    evidenceFrom(obs),
					Attributes:  map[string]string{"domains": joinList(names), "ip": ip, "sources": sourceList(obs)},
				})
			}
			return findings
		},
	}
}

func exposedPIIEmail() *rules.Rule {
	return &rules.Rule{
		ID:          "OSINT-003",
		Name:        "Personally identifying email exposed in public registries",
		Category:    "pii-exposure",
		Description: "An email address associated with the target appears in public WHOIS registry data or certificate logs, exposing a contact vector without authorization.",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfidenceObserved,
		Remediation: "Review registry privacy / redaction options and rotate any address reused for privileged accounts.",
		ObjectTypes: []string{"email"},
		Detect: func(ctx *rules.Context) []*models.Finding {
			var findings []*models.Finding
			for _, em := range ctx.Emails {
				if em == nil {
					continue
				}
				var obs []*models.Observation
				var exposedBy []string
				for _, o := range ctx.Observations {
					if o == nil || o.Key != "email" || !stringsEqualFold(o.Value, em.Address) {
						continue
					}
					obs = append(obs, o)
					if o.Source == "whois" || o.Source == "crt.sh" {
						exposedBy = append(exposedBy, o.Source)
					}
				}
				if len(exposedBy) == 0 {
					continue
				}
				seen := map[string]bool{}
				var uniq []string
				for _, s := range exposedBy {
					if !seen[s] {
						seen[s] = true
						uniq = append(uniq, s)
					}
				}
				sortStrings(uniq)
				findings = append(findings, &models.Finding{
					Title:       "Exposed email address " + em.Address,
					Category:    "pii-exposure",
					Description: "The address " + em.Address + " is recoverable from public sources (" + joinList(uniq) + ") without any privileged access.",
					Severity:    models.SeverityMedium,
					Confidence:  models.ConfidenceObserved,
					Status:      models.StatusDetected,
					State:       models.StateObserved,
					Objects:     []string{em.ID},
					Evidence:    evidenceFrom(obs),
					Attributes:  map[string]string{"email": em.Address, "sources": joinList(uniq)},
				})
			}
			return findings
		},
	}
}

func dnsWildcard() *rules.Rule {
	return &rules.Rule{
		ID:          "OSINT-004",
		Name:        "DNS wildcard resolves unknown hostnames",
		Category:    "dns-wildcard",
		Description: "The zone resolves arbitrary non-existent hostnames, which degrades passive hostname discovery and subdomain enumeration.",
		Severity:    models.SeverityInformational,
		Confidence:  models.ConfidenceObserved,
		Remediation: "Prefer explicit A/AAAA records; a wildcard hides 'did not exist' from 'did not resolve'.",
		ObjectTypes: []string{"domain"},
		Detect: func(ctx *rules.Context) []*models.Finding {
			if ctx == nil || ctx.Session == nil {
				return nil
			}
			if ctx.Session.Attributes["dns.wildcard"] != "true" {
				return nil
			}
			obs := ctx.ObservationsByKey("dns.wildcard")
			found := 0
			for _, o := range obs {
				if o != nil && o.Value == "true" {
					found++
				}
			}
			if found == 0 {
				return nil
			}
			return []*models.Finding{
				{
					Title:       "DNS wildcard in scope zone",
					Category:    "dns-wildcard",
					Description: "A wildcard record responds for unknown hostnames in the assessed zone; enumerate hostnames with care and treat DNS as authoritative only with corroboration.",
					Severity:    models.SeverityInformational,
					Confidence:  models.ConfidenceObserved,
					Status:      models.StatusInformational,
					State:       models.StateObserved,
					Objects:     []string{},
					Evidence:    evidenceFrom(obs),
					Attributes:  map[string]string{"wildcard": "true"},
				},
			}
		},
	}
}

// --- helpers ---------------------------------------------------------------

func observationsFor(ctx *rules.Context, key, value string) []*models.Observation {
	var out []*models.Observation
	for _, o := range ctx.Observations {
		if o != nil && o.Key == key && stringsEqualFold(o.Value, value) {
			out = append(out, o)
		}
	}
	return out
}

func observationsForKey(ctx *rules.Context, key, value string) []*models.Observation {
	return observationsFor(ctx, key, value)
}

func evidenceFrom(obs []*models.Observation) []models.Evidence {
	out := make([]models.Evidence, 0, len(obs))
	for _, o := range obs {
		if o != nil {
			out = append(out, rules.EvidenceForObservation(o))
		}
	}
	return out
}

func sourceList(obs []*models.Observation) string {
	seen := map[string]bool{}
	var out []string
	for _, o := range obs {
		if o != nil && !seen[o.Source] {
			seen[o.Source] = true
			out = append(out, o.Source)
		}
	}
	sortStrings(out)
	return joinList(out)
}

func distinctPlatforms(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range list {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sortStrings(out)
	return out
}

func joinList(list []string) string {
	out := ""
	for i, s := range list {
		if i > 0 {
			if i == len(list)-1 {
				out += " and "
			} else {
				out += ", "
			}
		}
		out += s
	}
	return out
}

func sortStrings(list []string) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j] < list[j-1]; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}

func stringsEqualFold(a, b string) bool {
	// ASCII fold (profile-safe): lowercase both.
	return foldASCII(a) == foldASCII(b)
}

func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
