package models

// SourceCategory groups a source by the type of data it provides.
type SourceCategory string

const (
	CategoryDNS         SourceCategory = "dns"
	CategoryCertificate SourceCategory = "certificate"
	CategoryRegistry    SourceCategory = "registry"
	CategoryCode        SourceCategory = "code"
	CategorySocial      SourceCategory = "social"
	CategoryIdentity    SourceCategory = "identity"
	CategoryNetwork     SourceCategory = "network"
	CategorySimulation  SourceCategory = "simulation"
)

// Source is the static contract a collector advertises: its identity, what
// it can do, whom it may touch, and its risk. It is the metadata backing both
// `nzinga sources list` and the capabilities catalog.
type Source struct {
	ID           string         `json:"id"` // stable identifier, e.g. "crt.sh"
	Name         string         `json:"name"`
	Description  string         `json:"description"`
	Category     SourceCategory `json:"category"`
	Capabilities []Capability   `json:"capabilities"`
	Output       []NodeKind     `json:"output,omitempty"` // entity kinds it produces
	Risk         RiskLevel      `json:"risk"`
	AuthRequired bool           `json:"auth_required"` // requires authorization gate
	Public       bool           `json:"public"`        // is a real public source (vs simulation)
	Targets      []TargetType   `json:"targets,omitempty"`
	RateLimit    string         `json:"rate_limit,omitempty"`
	Notes        string         `json:"notes,omitempty"`
}
