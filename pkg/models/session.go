package models

import "time"

// Session ties one intelligence run to a target and everything it learned:
// discovered entities, relationships, findings, evidence, observations and
// claims. It is the single source of truth for every output renderer.
type Session struct {
	ID       string `json:"id"`
	TargetID string `json:"target_id"`
	// Target is the human-readable typed target (e.g. "example.com (domain)").
	Target  string    `json:"target,omitempty"`
	Profile string    `json:"profile"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end,omitempty"`
	Stages  []string  `json:"stages,omitempty"`

	Domains        []*Domain        `json:"domains,omitempty"`
	Hostnames      []*Hostname      `json:"hostnames,omitempty"`
	IPs            []*IP            `json:"ips,omitempty"`
	People         []*Person        `json:"people,omitempty"`
	Emails         []*Email         `json:"emails,omitempty"`
	Usernames      []*Username      `json:"usernames,omitempty"`
	SocialAccounts []*SocialAccount `json:"social_accounts,omitempty"`
	Repositories   []*Repository    `json:"repositories,omitempty"`
	Certificates   []*Certificate   `json:"certificates,omitempty"`
	ASNs           []*ASN           `json:"asns,omitempty"`
	Organizations  []*Organization  `json:"organizations,omitempty"`

	Observations []*Observation `json:"observations,omitempty"`
	Claims       []*Claim       `json:"claims,omitempty"`

	Nodes []*Node `json:"graph_nodes,omitempty"`
	Edges []*Edge `json:"graph_edges,omitempty"`

	Findings []*Finding  `json:"findings,omitempty"`
	Evidence []*Evidence `json:"evidence,omitempty"`

	RiskScore int      `json:"risk_score,omitempty"`
	RiskLevel string   `json:"risk_level,omitempty"`
	OutputDir string   `json:"output_dir,omitempty"`
	Errors    []string `json:"errors,omitempty"`
	// Attributes carries summarized analysis context (claim summary,
	// correlation blurb) for reporting convenience.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// NewSession creates a session with a fresh identifier and the start time.
func NewSession() *Session {
	return &Session{
		ID:           NewID("sess"),
		Start:        time.Now().UTC(),
		Stages:       []string{},
		Findings:     []*Finding{},
		Evidence:     []*Evidence{},
		Errors:       []string{},
		Observations: []*Observation{},
		Claims:       []*Claim{},
	}
}

// AddFinding records a finding, merging duplicates by fingerprint.
func (s *Session) AddFinding(f *Finding) {
	if f == nil {
		return
	}
	f.SessionID = s.ID
	fp := f.Fingerprint()
	for _, existing := range s.Findings {
		if existing.Fingerprint() == fp {
			mergeEvidence(existing, f)
			return
		}
	}
	s.Findings = append(s.Findings, f)
}

// AddEvidence records an evidence item, deduplicating by hash.
func (s *Session) AddEvidence(ev *Evidence) {
	if ev == nil {
		return
	}
	for _, existing := range s.Evidence {
		if existing.Hash != "" && existing.Hash == ev.Hash {
			return
		}
	}
	s.Evidence = append(s.Evidence, ev)
}

// AddObservation records an observation, deduplicating by source, key, target
// and value. Target is part of the identity: the apex A record and a host's A
// record can carry the same value yet describe different relationships.
func (s *Session) AddObservation(o *Observation) {
	if o == nil {
		return
	}
	for _, existing := range s.Observations {
		if existing.Source == o.Source && existing.Key == o.Key && existing.Target == o.Target && existing.Value == o.Value {
			return
		}
	}
	s.Observations = append(s.Observations, o)
}

// AddClaim records a claim, deduplicating by type+subject+assertion.
func (s *Session) AddClaim(c *Claim) {
	if c == nil {
		return
	}
	for _, existing := range s.Claims {
		if existing.Type == c.Type && existing.Subject == c.Subject && existing.Assertion == c.Assertion {
			return
		}
	}
	s.Claims = append(s.Claims, c)
}

// AddEdge records a directed graph edge, merging identical edges.
func (s *Session) AddEdge(e *Edge) {
	if e == nil {
		return
	}
	for _, existing := range s.Edges {
		if existing.From == e.From && existing.To == e.To && existing.Type == e.Type {
			existing.EvidenceIDs = mergeStrings(existing.EvidenceIDs, e.EvidenceIDs...)
			existing.Confidence = existing.Confidence.Combined(e.Confidence)
			return
		}
	}
	s.Edges = append(s.Edges, e)
}

// AddNode records a graph node, deduplicating by id.
func (s *Session) AddNode(n *Node) {
	if n == nil {
		return
	}
	for _, existing := range s.Nodes {
		if existing.ID == n.ID {
			return
		}
	}
	s.Nodes = append(s.Nodes, n)
}

// Finish marks the session end time.
func (s *Session) Finish() { s.End = time.Now().UTC() }

func mergeStrings(dst []string, extras ...string) []string {
	seen := make(map[string]bool, len(dst))
	for _, s := range dst {
		seen[s] = true
	}
	for _, s := range extras {
		if !seen[s] {
			dst = append(dst, s)
			seen[s] = true
		}
	}
	return dst
}

func mergeEvidence(dst, src *Finding) {
	seen := make(map[string]bool, len(dst.Evidence))
	for _, ev := range dst.Evidence {
		seen[ev.ID] = true
	}
	for _, ev := range src.Evidence {
		if !seen[ev.ID] {
			dst.Evidence = append(dst.Evidence, ev)
			seen[ev.ID] = true
		}
	}
	if src.Confidence.Rank() > dst.Confidence.Rank() {
		dst.Confidence = src.Confidence
	}
}
