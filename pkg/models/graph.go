package models

import "time"

// NodeKind classifies a graph node.
type NodeKind string

const (
	NodeDomain        NodeKind = "domain"
	NodeHostname      NodeKind = "hostname"
	NodeIP            NodeKind = "ip"
	NodePerson        NodeKind = "person"
	NodeUsername      NodeKind = "username"
	NodeEmail         NodeKind = "email"
	NodeSocialAccount NodeKind = "social_account"
	NodeRepository    NodeKind = "repository"
	NodeCertificate   NodeKind = "certificate"
	NodeASN           NodeKind = "asn"
	NodeOrganization  NodeKind = "organization"
)

// RelationshipType is the directed edge vocabulary of the intelligence graph.
type RelationshipType string

const (
	RelResolvesTo   RelationshipType = "resolves_to"   // hostname → ip
	RelResolvesFrom RelationshipType = "resolves_from" // ip → hostname
	RelHosts        RelationshipType = "hosts"         // organization/asn/ip → hostname/ip
	RelOwes         RelationshipType = "belongs_to"    // email/account/username → person/domain/organization
	RelRegisters    RelationshipType = "registers"     // organization/person → domain
	RelOwns         RelationshipType = "owns"          // organization/person → repository/domain
	RelUses         RelationshipType = "uses"          // hostname/domain → certificate/social_account
	RelControls     RelationshipType = "controls"      // asn → ip
	RelAttributedTo RelationshipType = "attributed_to" // repository/social_account → person/username
	RelRelated      RelationshipType = "related"       // generic co-occurrence
)

// Node is one vertex in the intelligence graph.
type Node struct {
	ID        string    `json:"id"`
	Kind      NodeKind  `json:"kind"`
	Label     string    `json:"label"`
	Source    string    `json:"source,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Edge is one directed relationship between two nodes.
type Edge struct {
	ID          string           `json:"id"`
	From        string           `json:"from"`
	To          string           `json:"to"`
	Type        RelationshipType `json:"type"`
	Source      string           `json:"source,omitempty"` // evidence/collection source
	Confidence  Confidence       `json:"confidence,omitempty"`
	EvidenceIDs []string         `json:"evidence_ids,omitempty"`
	Timestamp   time.Time        `json:"timestamp"`
}
