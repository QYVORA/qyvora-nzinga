package models

import "time"

// TargetType distinguishes the kind of entity an intelligence run operates on.
type TargetType string

const (
	// TargetDomain identifies a DNS domain (e.g. domain:example.com).
	TargetDomain TargetType = "domain"
	// TargetOrganization identifies an organization (e.g. org:Acme).
	TargetOrganization TargetType = "organization"
	// TargetUsername identifies a username/platform handle (e.g. username:alice).
	TargetUsername TargetType = "username"
	// TargetIP identifies an IP address (e.g. ip:192.0.2.10).
	TargetIP TargetType = "ip"
	// TargetInfrastructure identifies a running target of infrastructure type
	// (e.g. infra:example.com) whose entities resolve through hosting lookups.
	TargetInfrastructure TargetType = "infrastructure"
)

// ParseTargetType converts a case-insensitive type string; empty returns
// TargetDomain (the CLI default for bare names).
func ParseTargetType(s string) TargetType {
	switch TargetType(s) {
	case TargetDomain, TargetOrganization, TargetUsername, TargetIP, TargetInfrastructure:
		return TargetType(s)
	default:
		return TargetDomain
	}
}

// Authorization records the explicit consent state of a target. Live
// collection must begin with an authorized target; the framework refuses to
// execute live sources otherwise. The simulation source is the only source
// that runs without authorization.
type Authorization struct {
	Granted   bool      `json:"granted"`
	GrantedAt time.Time `json:"granted_at,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	GrantedBy string    `json:"granted_by,omitempty"`
	Method    string    `json:"method,omitempty"`
}

// Target is the normalized object an intelligence run operates on. It carries
// the resolved entity value, the assessment profile, and the explicit
// authorization gate.
type Target struct {
	ID        string        `json:"id"`
	Name      string        `json:"name,omitempty"`
	Type      TargetType    `json:"type"`
	Value     string        `json:"value"`
	Auth      Authorization `json:"authorization"`
	Profile   string        `json:"profile,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
}

// Authorized reports whether the target passed the authorization gate.
func (t *Target) Authorized() bool { return t != nil && t.Auth.Granted }

// DisplayName returns a short human-readable label for the target.
func (t *Target) DisplayName() string {
	if t == nil {
		return "<nil>"
	}
	if t.Name != "" {
		return t.Name
	}
	if t.Value != "" {
		return t.Value
	}
	return "unknown target"
}

// TypedName renders the target with its type prefix, e.g. "domain:example.com".
func (t *Target) TypedName() string {
	if t == nil {
		return "<nil>"
	}
	if t.Value == "" {
		return string(t.Type)
	}
	return string(t.Type) + ":" + t.Value
}
