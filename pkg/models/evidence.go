package models

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// EvidenceKind classifies how a piece of evidence was obtained.
type EvidenceKind string

const (
	EvidenceAttribute     EvidenceKind = "attribute"
	EvidenceObservation   EvidenceKind = "observation"
	EvidenceConfiguration EvidenceKind = "configuration"
	EvidenceService       EvidenceKind = "service"
	EvidenceRelationship  EvidenceKind = "relationship"
)

// Evidence is one verifiable observation backing a finding, claim, or
// relationship. It is immutable once recorded within a session. Reports trace
// finding → evidence → observed entity → collection source.
type Evidence struct {
	ID           string       `json:"id"`
	Kind         EvidenceKind `json:"kind"`
	Source       string       `json:"source"`                // collection source, e.g. "crt.sh"
	SourceID     string       `json:"source_id,omitempty"`   // internal source id
	SourceType   string       `json:"source_type,omitempty"` // claimed source taxonomy
	Target       string       `json:"target,omitempty"`
	Data         string       `json:"data,omitempty"`
	Hash         string       `json:"hash"`
	RawReference string       `json:"raw_reference,omitempty"` // pointer to raw record (URL/object key)
	State        State        `json:"state"`
	ObservedAt   time.Time    `json:"observed_at,omitempty"`
	CollectedAt  time.Time    `json:"collected_at,omitempty"`
	Timestamp    time.Time    `json:"timestamp"`
}

// HashContent returns the lowercase hex SHA-256 digest of s.
func HashContent(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
