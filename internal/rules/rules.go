// Package rules implements the deterministic finding engine. A rule inspects
// a session and produces findings; evaluation is deterministic and
// deduplicated by fingerprint, never by map iteration order.
package rules

import (
	"sort"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// Rule describes one detection. Detect must be pure: same session, same
// findings. Findings are merged by fingerprint when added to a session.
type Rule struct {
	ID            string
	Name          string
	Category      string
	Description   string
	Severity      models.Severity
	Confidence    models.Confidence
	RequiredState models.State
	ObjectTypes   []string
	Detect        func(ctx *Context) []*models.Finding
	Remediation   string
	References    []string
}

// Context wraps the session the rules evaluate against. It exposes stable,
// deduplicated views of the discovered entities rather than raw slices.
type Context struct {
	Session *models.Session

	Domains       []*models.Domain
	Hostnames     []*models.Hostname
	IPs           []*models.IP
	Usernames     []*models.Username
	Emails        []*models.Email
	Organizations []*models.Organization
	Observations  []*models.Observation
	Edges         []*models.Edge
}

// NewContext builds an evaluation context from a session.
func NewContext(sess *models.Session) *Context {
	c := &Context{Session: sess}
	if sess == nil {
		return c
	}
	c.Domains = append([]*models.Domain(nil), sess.Domains...)
	c.Hostnames = append([]*models.Hostname(nil), sess.Hostnames...)
	c.IPs = append([]*models.IP(nil), sess.IPs...)
	c.Usernames = append([]*models.Username(nil), sess.Usernames...)
	c.Emails = append([]*models.Email(nil), sess.Emails...)
	c.Organizations = append([]*models.Organization(nil), sess.Organizations...)
	c.Observations = append([]*models.Observation(nil), sess.Observations...)
	c.Edges = append([]*models.Edge(nil), sess.Edges...)
	return c
}

// Engine evaluates a set of rules against a context.
type Engine struct {
	rules []*Rule
}

// NewEngine returns an empty engine.
func NewEngine() *Engine { return &Engine{} }

// Add registers a rule.
func (e *Engine) Add(r *Rule) *Engine {
	if r != nil {
		e.rules = append(e.rules, r)
	}
	return e
}

// AddMany registers many rules.
func (e *Engine) AddMany(rs []*Rule) *Engine {
	for _, r := range rs {
		e.Add(r)
	}
	return e
}

// Rules returns the registered rules in registration order.
func (e *Engine) Rules() []*Rule { return e.rules }

// Eval runs every rule against the context. Ordering is fixed by rule
// registration; findings are sorted by (severity, rule, title) and each
// finding is bound to the target/session identifiers.
func (e *Engine) Eval(ctx *Context, targetID, sessionID string) []*models.Finding {
	var out []*models.Finding
	for _, r := range e.rules {
		if r == nil || r.Detect == nil {
			continue
		}
		for _, f := range r.Detect(ctx) {
			f.RuleID = r.ID
			f.SessionID = sessionID
			f.TargetID = targetID
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity.Weights() != out[j].Severity.Weights() {
			return out[i].Severity.Weights() > out[j].Severity.Weights()
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// ObservationsByKey returns observations matching a key, in session order.
func (c *Context) ObservationsByKey(key string) []*models.Observation {
	var out []*models.Observation
	for _, o := range c.Observations {
		if o != nil && o.Key == key {
			out = append(out, o)
		}
	}
	return out
}

// EdgeExists reports a directed edge (from ID -> to ID, type).
func (c *Context) EdgeExists(from, to string, typ models.RelationshipType) bool {
	for _, e := range c.Edges {
		if e != nil && e.From == from && e.To == to && e.Type == typ {
			return true
		}
	}
	return false
}

// EvidenceForObservation converts an observation into an evidence stub for a
// finding, preserving the observation's source provenance.
func EvidenceForObservation(o *models.Observation) models.Evidence {
	ev := models.Evidence{
		ID:           models.NewID("ev"),
		Kind:         models.EvidenceObservation,
		Source:       o.Source,
		SourceID:     o.SourceID,
		SourceType:   o.SourceType,
		Target:       o.Target,
		Data:         strings.TrimSpace(o.Key + "=" + o.Value),
		Hash:         models.HashContent(o.Source + "\x00" + o.Target + "\x00" + o.Key + "\x00" + o.Value),
		RawReference: o.RawReference,
		State:        o.State,
		ObservedAt:   o.ObservedAt,
		CollectedAt:  o.CollectedAt,
		Timestamp:    o.Timestamp,
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	return ev
}
