// Package capabilities advertises what nzinga can do as a machine-readable
// tool contract. The catalog is derived from the sources, safety operations,
// and builtin rules rather than a parallel hand-maintained list, so the
// advertised contract cannot drift from the implementation.
package capabilities

import (
	"sort"
	"strings"

	"github.com/QYVORA/qyvora-nzinga/internal/rules"
	"github.com/QYVORA/qyvora-nzinga/internal/rules/builtin"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// Param is one input parameter a tool accepts.
type Param struct {
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Description string `json:"description,omitempty"`
}

// OutputField is one field of the record a tool returns.
type OutputField struct {
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
}

// Schema is the structured interface contract for a tool: the inputs it
// accepts and the shape of the records it produces.
type Schema struct {
	Input  []Param       `json:"input"`
	Output []OutputField `json:"output"`
}

// Tool is the machine- and human-readable contract for one capability. It is
// the schema an agent or automation can consume to decide whether nzinga can
// fulfil a request and what authorization it needs.
type Tool struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	Framework    string            `json:"framework"`
	Category     string            `json:"category"`
	Output       []string          `json:"output,omitempty"`
	Risk         models.RiskLevel  `json:"risk"`
	AuthRequired bool              `json:"authorization_required"`
	Confirm      bool              `json:"confirmation_required"`
	Reversible   bool              `json:"reversible"`
	ChangesState bool              `json:"changes_state"`
	Targets      []string          `json:"target_types,omitempty"`
	Duration     string            `json:"duration,omitempty"`
	Capability   models.Capability `json:"capability"`
	Schema       Schema            `json:"schema"`
}

// Catalog assembles the tool contract for every source capability, plus the
// analysis tool, plus the builtin rules as detection capabilities.
func Catalog(sources []models.Source, rules []*rules.Rule) []Tool {
	var out []Tool

	// One tool per (source, capability) pair.
	for _, s := range sources {
		byCap := groupCaps(s.Capabilities)
		for _, capStr := range models.AllCapabilities {
			if !byCap[capStr] {
				continue
			}
			out = append(out, Tool{
				ID:           "nzinga." + s.ID + "." + string(capStr),
				Name:         s.Name + " — " + string(capStr),
				Description:  s.Description,
				Framework:    "nzinga",
				Category:     string(s.Category),
				Output:       outputKinds(s.Output),
				Risk:         s.Risk,
				AuthRequired: s.AuthRequired,
				Confirm:      false,
				Reversible:   true,
				ChangesState: false,
				Targets:      stringList(s.Targets),
				Duration:     secondsHint(s),
				Capability:   capStr,
				Schema:       observationSchema(stringList(s.Targets)),
			})
		}
	}

	// The analysis/correlation capability is a first-class tool.
	out = append(out, Tool{
		ID:           "nzinga.analyze.correlate",
		Name:         "Correlate observations into claims and findings",
		Description:  "Run correlation and the builtin rules over a session to produce claims and evidence-backed findings.",
		Framework:    "nzinga",
		Category:     "analysis",
		Output:       []string{"findings", "claims"},
		Risk:         models.RiskS1,
		AuthRequired: true,
		Confirm:      false,
		Reversible:   true,
		ChangesState: false,
		Targets:      []string{"domain", "organization", "username", "ip", "infrastructure"},
		Duration:     "instant",
		Capability:   models.CapAnalysis,
		Schema: Schema{
			Input: []Param{
				{Name: "session", Type: "session", Required: true, Description: "the collected session to analyze"},
			},
			Output: []OutputField{
				{Name: "findings", Type: "array[finding]", Description: "detected findings with risk, evidence and confidence"},
				{Name: "claims", Type: "array[claim]", Description: "higher-level assertions traced to observations"},
			},
		},
	})

	// Rules surface as detection capabilities.
	for _, r := range rules {
		if r == nil {
			continue
		}
		out = append(out, Tool{
			ID:           "nzinga.rule." + r.ID,
			Name:         r.Name,
			Description:  r.Description,
			Framework:    "nzinga",
			Category:     "detection",
			Output:       []string{"finding"},
			Risk:         models.RiskS1,
			AuthRequired: true,
			Confirm:      false,
			Reversible:   true,
			ChangesState: false,
			Targets:      r.ObjectTypes,
			Duration:     "instant",
			Capability:   models.CapAnalysis,
			Schema: Schema{
				Input: []Param{
					{Name: "session", Type: "session", Required: true, Description: "the normalized session to detect against"},
				},
				Output: []OutputField{
					{Name: "finding", Type: "finding", Description: "one evidence-backed detection"},
				},
			},
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// CapabilityAnalysis is the analysis capability constant re-exported for the
// catalog (see models).
const CapabilityAnalysis models.Capability = "analysis"

// New returns the catalog deterministically from the shipped sources/rules.
// The sources argument should be the registry's List() output.
func New(sources []models.Source) []Tool {
	return Catalog(sources, builtin.All())
}

func groupCaps(caps []models.Capability) map[models.Capability]bool {
	m := map[models.Capability]bool{}
	for _, c := range caps {
		m[c] = true
	}
	return m
}

// observationSchema is the shared schema for collection capabilities: they
// consume a target value and emit normalized observations with provenance.
func observationSchema(targets []string) Schema {
	input := []Param{{
		Name:        "target",
		Type:        "string",
		Required:    true,
		Description: "the " + strings.Join(targets, "/") + " value to collect against",
	}}
	output := []OutputField{
		{Name: "id", Type: "string", Description: "observation id"},
		{Name: "source", Type: "string", Description: "collection source name"},
		{Name: "source_type", Type: "string", Description: "source taxonomy (e.g. cert, dns, whois)"},
		{Name: "capability", Type: "capability", Description: "collection capability invoked"},
		{Name: "target", Type: "string", Description: "the target the record belongs to"},
		{Name: "key", Type: "string", Description: "typed field, e.g. A, hostname, email"},
		{Name: "value", Type: "string", Description: "normalized value"},
		{Name: "state", Type: "state", Description: "observed | inferred | denied"},
		{Name: "confidence", Type: "confidence", Description: "observed | high | medium | low | inferred | possible"},
		{Name: "observed_at", Type: "datetime", Description: "when the fact was first observed"},
		{Name: "collected_at", Type: "datetime", Description: "when the source captured it"},
		{Name: "timestamp", Type: "datetime", Description: "when nzinga recorded it"},
		{Name: "raw_reference", Type: "string", Description: "pointer to the raw record, e.g. crt.sh query URL"},
		{Name: "hash", Type: "string", Description: "sha256 content hash for integrity"},
	}
	return Schema{Input: input, Output: output}
}

func outputKinds(kinds []models.NodeKind) []string {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return out
}

func stringList(list []models.TargetType) []string {
	out := make([]string, 0, len(list))
	for _, t := range list {
		out = append(out, string(t))
	}
	return out
}

func secondsHint(s models.Source) string {
	if s.ID == "simulation" {
		return "instant (offline)"
	}
	return "profile-dependent"
}

// ContractVersion is the version of the capabilities contract schema.
const ContractVersion = "1.0"
