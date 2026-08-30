package models

import "time"

// Capability is a collection capability advertised by a source. The set is
// the agreed OSINT capability vocabulary:
//
//	domain.enumerate      discover sibling/related domains
//	subdomain.enumerate   discover hostnames under a domain
//	dns.resolve           resolve A/AAAA/NS/MX/TXT/CNAME records
//	whois.lookup          registry/whois metadata for a domain or IP
//	ip.lookup             reverse/geo/asn metadata for an IP
//	asn.lookup            AS number prefixes and ownership
//	certificate.enumerate enumerate certificates (and their SAN names)
//	username.lookup       find a username across platforms
//	repository.enumerate  enumerate public code repositories
//	email.enumerate       discover email addresses from public sources
type Capability string

const (
	CapDomainEnumerate    Capability = "domain.enumerate"
	CapSubdomainEnumerate Capability = "subdomain.enumerate"
	CapDNSResolve         Capability = "dns.resolve"
	CapWhoisLookup        Capability = "whois.lookup"
	CapIPLookup           Capability = "ip.lookup"
	CapASNLookup          Capability = "asn.lookup"
	CapCertEnumerate      Capability = "certificate.enumerate"
	CapUsernameLookup     Capability = "username.lookup"
	CapRepoEnumerate      Capability = "repository.enumerate"
	CapEmailEnumerate     Capability = "email.enumerate"
	// CapAnalysis is the framework-internal correlation/analysis capability
	// (not a collection source capability).
	CapAnalysis Capability = "analysis"
)

// AllCapabilities lists every capability in stable order, used by the
// capabilities catalog and documentation.
var AllCapabilities = []Capability{
	CapDomainEnumerate,
	CapSubdomainEnumerate,
	CapDNSResolve,
	CapWhoisLookup,
	CapIPLookup,
	CapASNLookup,
	CapCertEnumerate,
	CapUsernameLookup,
	CapRepoEnumerate,
	CapEmailEnumerate,
}

// ClaimType classifies the assertion a Claim makes about its subject.
type ClaimType string

const (
	ClaimIdentity       ClaimType = "identity"       // entity identity or reuse (e.g. username reuse)
	ClaimInfrastructure ClaimType = "infrastructure" // hosting/ASN/IP relationship
	ClaimAttribution    ClaimType = "attribution"    // entity <-> person/org relationship
	ClaimExposure       ClaimType = "exposure"       // sensitive data observable publicly
	ClaimConsistency    ClaimType = "consistency"    // entities agree/differ across sources
)

// Observation is one atomic, normalized data point collected from a source:
// for example one certificate SAN, one A record, one whois field. It is the
// input to normalization, which groups observations into claims.
type Observation struct {
	ID           string            `json:"id"`
	Source       string            `json:"source"`                // collection source, e.g. "crt.sh"
	SourceID     string            `json:"source_id,omitempty"`   // internal source id
	SourceType   string            `json:"source_type,omitempty"` // claimed source taxonomy, e.g. "cert", "dns"
	Capability   Capability        `json:"capability,omitempty"`
	Target       string            `json:"target,omitempty"`
	Key          string            `json:"key,omitempty"` // typed field (e.g. "A", "nameserver", "email")
	Value        string            `json:"value"`         // normalized value
	State        State             `json:"state"`
	Confidence   Confidence        `json:"confidence,omitempty"`
	Claim        string            `json:"claim,omitempty"`         // short human assertion this observation supports
	Raw          map[string]string `json:"raw,omitempty"`           // source-specific provenance
	RawReference string            `json:"raw_reference,omitempty"` // pointer to raw record (URL/object key)
	ObservedAt   time.Time         `json:"observed_at,omitempty"`
	CollectedAt  time.Time         `json:"collected_at,omitempty"` // when the source captured it
	Timestamp    time.Time         `json:"timestamp"`              // when nzinga recorded it
}

// Claim is a higher-level assertion the framework forms from observations:
// "username alice is active on platforms X, Y". Claims carry explicit
// confidence and trace back to their observations.
type Claim struct {
	ID             string            `json:"id"`
	Type           ClaimType         `json:"type"`
	Subject        string            `json:"subject"` // entity identifier (or handle)
	Assertion      string            `json:"assertion"`
	Confidence     Confidence        `json:"confidence"`
	State          State             `json:"state"`
	ObservationIDs []string          `json:"observation_ids,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
}
