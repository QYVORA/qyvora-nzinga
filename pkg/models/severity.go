package models

import "strings"

// Severity describes the security or business impact of a finding.
type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInformational Severity = "informational"
)

// ParseSeverity converts a case-insensitive string into a Severity,
// defaulting to Informational for unknown input.
func ParseSeverity(s string) Severity {
	norm := Severity(strings.ToLower(s))
	switch norm {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational:
		return norm
	default:
		return SeverityInformational
	}
}

// Weights returns a numeric weight used to sort findings. Higher is worse.
func (s Severity) Weights() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// SortRank returns the rank used when ordering findings.
func (s Severity) SortRank() int { return s.Weights() }

// Valid reports whether s is a recognized severity value.
func (s Severity) Valid() bool { return s == SeverityCritical || s.Weights() != 0 }

// SeverityCounts summarizes how many findings exist at each severity.
type SeverityCounts struct {
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Informational int `json:"informational"`
}

// Tally returns the total number of findings represented by the counts.
func (c SeverityCounts) Tally() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Informational
}
