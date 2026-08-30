package models

import "strings"

// Confidence expresses how sure the framework is that an observation, claim,
// or finding is genuine. Nzinga uses seven values that reflect the OSINT
// evidence discipline: absence is never reported as absence-proof, and no
// value is ever escalated beyond what the evidence supports.
type Confidence string

const (
	ConfidenceConfirmed   Confidence = "confirmed"    // multiple independent sources agree or direct authoritative record
	ConfidenceObserved    Confidence = "observed"     // seen in at least one primary source
	ConfidenceProbable    Confidence = "probable"     // strong but not direct evidence (e.g. inferred from multiple)
	ConfidencePossible    Confidence = "possible"     // weak or single-source inference
	ConfidenceUnknown     Confidence = "unknown"      // insufficient information to judge
	ConfidenceNotObserved Confidence = "not_observed" // an absence of observation — never treated as absence proof
)

// ParseConfidence converts a case-insensitive string into a Confidence,
// defaulting to Unknown for unrecognized input.
func ParseConfidence(s string) Confidence {
	norm := Confidence(strings.ToLower(s))
	switch norm {
	case ConfidenceConfirmed, ConfidenceObserved, ConfidenceProbable,
		ConfidencePossible, ConfidenceUnknown, ConfidenceNotObserved:
		return norm
	default:
		return ConfidenceUnknown
	}
}

// Rank orders confidence values weakest to strongest. NotObserved sits below
// Unknown: it carries negative information (we did not see it), which is the
// least claim the framework will make.
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceConfirmed:
		return 6
	case ConfidenceObserved:
		return 5
	case ConfidenceProbable:
		return 4
	case ConfidencePossible:
		return 3
	case ConfidenceUnknown:
		return 2
	case ConfidenceNotObserved:
		return 1
	default:
		return 0
	}
}

// Valid reports whether c is a recognized confidence value.
func (c Confidence) Valid() bool { return c.Rank() != 0 }

// Combined returns the stronger of two confidence values.
func (a Confidence) Combined(b Confidence) Confidence {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}
