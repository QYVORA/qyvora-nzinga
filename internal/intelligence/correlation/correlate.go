// Package correlation turns normalized observations into claims. Claims are
// the framework's explicit assertions ("handle X appears on platforms A, B")
// with visible confidence and traceable observations. Rule-driven findings are
// the pipeline's ANALYZE stage, which is separate so each stage does one thing.
package correlation

import (
	"sort"
	"time"

	"github.com/QYVORA/qyvora-nzinga/internal/events"
	"github.com/QYVORA/qyvora-nzinga/internal/rules"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// Engine correlates a session.
type Engine struct {
	events *events.Stream
}

// New returns a correlation engine.
func New(ev *events.Stream) *Engine { return &Engine{events: ev} }

// Run derives claims from the session's normalized entities and stores them.
func (e *Engine) Run(sess *models.Session) []*models.Claim {
	if sess == nil {
		return nil
	}

	ctx := rules.NewContext(sess)
	claims := buildClaims(ctx)
	for _, c := range claims {
		sess.AddClaim(c)
		if e.events != nil {
			e.events.Info(events.ClaimCreated, map[string]any{
				"type": c.Type, "subject": c.Subject, "assertion": c.Assertion, "confidence": c.Confidence,
			})
		}
	}
	if e.events != nil {
		e.events.Info(events.AnalysisCompleted, map[string]any{
			"claims": len(sess.Claims),
		})
	}
	return claims
}

// buildClaims derives the framework's explicit assertions from the session.
// Each claim degrades honestly: it references only collected observations.
func buildClaims(ctx *rules.Context) []*models.Claim {
	var out []*models.Claim
	now := time.Now().UTC()

	for _, u := range ctx.Usernames {
		if u == nil || len(u.Platforms) < 2 {
			continue
		}
		platforms := dedupeSorted(u.Platforms)
		out = append(out, &models.Claim{
			ID:             models.NewID("clm"),
			Type:           models.ClaimIdentity,
			Subject:        u.Handle,
			Assertion:      "handle " + u.Handle + " is active on " + join(platforms),
			Confidence:     models.ConfidenceProbable,
			State:          models.StateObserved,
			ObservationIDs: observationIDs(ctx, "username", u.Handle),
			CreatedAt:      now,
		})
	}

	shared := sharedHostingDomains(ctx)
	for _, s := range shared {
		out = append(out, &models.Claim{
			ID:             models.NewID("clm"),
			Type:           models.ClaimInfrastructure,
			Subject:        s.IP,
			Assertion:      "domains " + join(s.Domains) + " share address " + s.IP,
			Confidence:     models.ConfidenceProbable,
			State:          models.StateObserved,
			ObservationIDs: observationIDsForIP(ctx, s.IP),
			CreatedAt:      now,
		})
	}

	for _, em := range ctx.Emails {
		if em == nil {
			continue
		}
		var obs []*models.Observation
		for _, o := range ctx.Observations {
			if o != nil && o.Key == "email" && foldASCII(o.Value) == foldASCII(em.Address) &&
				(o.Source == "whois" || o.Source == "crt.sh") {
				obs = append(obs, o)
			}
		}
		if len(obs) == 0 {
			continue
		}
		ids := make([]string, 0, len(obs))
		for _, o := range obs {
			ids = append(ids, o.ID)
		}
		out = append(out, &models.Claim{
			ID:             models.NewID("clm"),
			Type:           models.ClaimExposure,
			Subject:        em.Address,
			Assertion:      "email " + em.Address + " is recoverable from public sources",
			Confidence:     models.ConfidenceObserved,
			State:          models.StateObserved,
			ObservationIDs: ids,
			CreatedAt:      now,
		})
	}
	return out
}

type sharedHost struct {
	IP      string
	Domains []string
}

func sharedHostingDomains(ctx *rules.Context) []sharedHost {
	domByID := map[string]string{}
	for _, d := range ctx.Domains {
		if d != nil {
			domByID[d.ID] = d.Name
		}
	}
	hnDomain := map[string]string{}
	for _, e := range ctx.Edges {
		if e != nil && e.Type == models.RelOwes {
			if _, ok := domByID[e.To]; ok {
				hnDomain[e.From] = e.To
			}
		}
	}
	ipDoms := map[string]map[string]bool{}
	for _, e := range ctx.Edges {
		if e == nil || e.Type != models.RelResolvesTo {
			continue
		}
		domID, ok := hnDomain[e.From]
		if !ok {
			continue
		}
		dom, ok := domByID[domID]
		if !ok {
			continue
		}
		if ipDoms[e.To] == nil {
			ipDoms[e.To] = map[string]bool{}
		}
		ipDoms[e.To][dom] = true
	}
	var out []sharedHost
	for ip, doms := range ipDoms {
		names := make([]string, 0, len(doms))
		for d := range doms {
			names = append(names, d)
		}
		sort.Strings(names)
		if len(names) >= 2 {
			out = append(out, sharedHost{IP: ip, Domains: names})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func observationIDs(ctx *rules.Context, key, value string) []string {
	var out []string
	for _, o := range ctx.Observations {
		if o != nil && o.Key == key && foldASCII(o.Value) == foldASCII(value) {
			out = append(out, o.ID)
		}
	}
	return out
}

func observationIDsForIP(ctx *rules.Context, ip string) []string {
	var out []string
	for _, o := range ctx.Observations {
		if o != nil && (o.Key == "a" || o.Key == "aaaa" || o.Key == "ip") && o.Value == ip {
			out = append(out, o.ID)
		}
	}
	return out
}

func dedupeSorted(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range list {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func join(list []string) string {
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

func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
