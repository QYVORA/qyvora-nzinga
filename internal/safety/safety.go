// Package safety implements the architectural safety model of nzinga.
//
// Every meaningful collection operation carries metadata describing its
// class, risk, target type, authorization requirement, whether it changes
// the remote state, and whether it is reversible. OSINT collection from
// public sources is read-mostly and reversible; the gate is authorization,
// not technical escalation.
package safety

import "github.com/QYVORA/qyvora-nzinga/pkg/models"

// Class identifies a family of collection/analysis operation.
type Class string

const (
	ClassDiscovery Class = "discovery"
	ClassEnumerat  Class = "enumeration"
	ClassAnalysis  Class = "analysis"
)

// OperationMetadata describes one operation's safety contract. Every nzinga
// source operation is read-only, reversible, and never changes remote state.
type OperationMetadata struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	Class        Class            `json:"class"`
	Risk         models.RiskLevel `json:"risk"`
	TargetType   string           `json:"target_type"`
	AuthRequired bool             `json:"authorization_required"`
	Confirm      bool             `json:"confirmation_required"`
	ChangesState bool             `json:"changes_state"`
	Reversible   bool             `json:"reversible"`
}

// Known operations. All are read-only and reversible.
var (
	OpCertEnumerate = OperationMetadata{
		ID: "nzinga.certificate.enumerate", Name: "certificate transparency enumeration",
		Description: "Query a certificate transparency log for certificates matching a domain.",
		Class:       ClassDiscovery, Risk: models.RiskS1, TargetType: "domain",
		AuthRequired: true, Confirm: false, ChangesState: false, Reversible: true,
	}
	OpDNSResolve = OperationMetadata{
		ID: "nzinga.dns.resolve", Name: "dns resolution",
		Description: "Resolve DNS records for discovered hostnames.",
		Class:       ClassDiscovery, Risk: models.RiskS1, TargetType: "domain",
		AuthRequired: true, Confirm: false, ChangesState: false, Reversible: true,
	}
	OpWhoisLookup = OperationMetadata{
		ID: "nzinga.whois.lookup", Name: "whois lookup",
		Description: "Query registry WHOIS metadata for a domain.",
		Class:       ClassDiscovery, Risk: models.RiskS1, TargetType: "domain",
		AuthRequired: true, Confirm: false, ChangesState: false, Reversible: true,
	}
	OpUsernameEnumerate = OperationMetadata{
		ID: "nzinga.username.enumerate", Name: "username enumeration",
		Description: "Look up a username across public platforms.",
		Class:       ClassDiscovery, Risk: models.RiskS1, TargetType: "username",
		AuthRequired: true, Confirm: false, ChangesState: false, Reversible: true,
	}
	OpAnalyze = OperationMetadata{
		ID: "nzinga.analyze", Name: "correlation and analysis",
		Description: "Correlate observations into claims and rule findings.",
		Class:       ClassAnalysis, Risk: models.RiskS1, TargetType: "any",
		AuthRequired: true, Confirm: false, ChangesState: false, Reversible: true,
	}
)

// IsAllowed reports whether an operation may run under the given posture.
// All initial operations are S1 read-only, so the safe default posture is
// satisfied without sacrificing capability.
func IsAllowed(op OperationMetadata, safeOnly bool) bool {
	if safeOnly && op.Risk.Rank() >= models.RiskS3.Rank() {
		return false
	}
	return !op.ChangesState || op.Reversible
}
