package models

import "time"

// Entity is the optional common surface for discovered intelligence entities.
// It is implemented by the concrete entity types below. Every entity tracks
// how it was learned (State/Confidence) and from which sources.
type Entity interface {
	EntityID() string
	EntityKind() NodeKind
}

// Domain describes a DNS domain observed in open sources.
type Domain struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"` // normalized, lowercase FQDN
	State        State      `json:"state"`
	Confidence   Confidence `json:"confidence,omitempty"`
	Sources      []string   `json:"sources,omitempty"`
	Organization string     `json:"organization,omitempty"`
	DiscoveredAt time.Time  `json:"discovered_at"`
}

// EntityID implements Entity.
func (d *Domain) EntityID() string { return d.ID }

// EntityKind implements Entity.
func (d *Domain) EntityKind() NodeKind { return NodeDomain }

// Hostname describes a discovered host within a domain.
type Hostname struct {
	ID           string     `json:"id"`
	FQDN         string     `json:"fqdn"` // fully qualified, normalized
	Domain       string     `json:"domain,omitempty"`
	State        State      `json:"state"`
	Confidence   Confidence `json:"confidence,omitempty"`
	Sources      []string   `json:"sources,omitempty"`
	DiscoveredAt time.Time  `json:"discovered_at"`
}

// EntityID implements Entity.
func (h *Hostname) EntityID() string { return h.ID }

// EntityKind implements Entity.
func (h *Hostname) EntityKind() NodeKind { return NodeHostname }

// IP describes an IPv4/IPv6 address observed in open sources.
type IP struct {
	ID           string     `json:"id"`
	Address      string     `json:"address"`
	Version      int        `json:"version,omitempty"` // 4 or 6
	ASN          string     `json:"asn,omitempty"`
	State        State      `json:"state"`
	Confidence   Confidence `json:"confidence,omitempty"`
	Sources      []string   `json:"sources,omitempty"`
	DiscoveredAt time.Time  `json:"discovered_at"`
}

// EntityID implements Entity.
func (i *IP) EntityID() string { return i.ID }

// EntityKind implements Entity.
func (i *IP) EntityKind() NodeKind { return NodeIP }

// Organization describes an organization observed in open sources.
type Organization struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Aliases      []string   `json:"aliases,omitempty"`
	State        State      `json:"state"`
	Confidence   Confidence `json:"confidence,omitempty"`
	Sources      []string   `json:"sources,omitempty"`
	DiscoveredAt time.Time  `json:"discovered_at"`
}

// EntityID implements Entity.
func (o *Organization) EntityID() string { return o.ID }

// EntityKind implements Entity.
func (o *Organization) EntityKind() NodeKind { return NodeOrganization }

// Person describes a natural person observed across open sources.
type Person struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Aliases      []string   `json:"aliases,omitempty"`
	State        State      `json:"state"`
	Confidence   Confidence `json:"confidence,omitempty"`
	Sources      []string   `json:"sources,omitempty"`
	DiscoveredAt time.Time  `json:"discovered_at"`
}

// EntityID implements Entity.
func (p *Person) EntityID() string { return p.ID }

// EntityKind implements Entity.
func (p *Person) EntityKind() NodeKind { return NodePerson }

// Email describes an email address observed in open sources.
type Email struct {
	ID           string     `json:"id"`
	Address      string     `json:"address"`
	Local        string     `json:"local,omitempty"`
	Domain       string     `json:"domain,omitempty"`
	State        State      `json:"state"`
	Confidence   Confidence `json:"confidence,omitempty"`
	Sources      []string   `json:"sources,omitempty"`
	DiscoveredAt time.Time  `json:"discovered_at"`
}

// EntityID implements Entity.
func (e *Email) EntityID() string { return e.ID }

// EntityKind implements Entity.
func (e *Email) EntityKind() NodeKind { return NodeEmail }

// Username describes a username/handle observed across platform sources.
type Username struct {
	ID           string     `json:"id"`
	Handle       string     `json:"handle"`
	Platforms    []string   `json:"platforms,omitempty"`
	State        State      `json:"state"`
	Confidence   Confidence `json:"confidence,omitempty"`
	Sources      []string   `json:"sources,omitempty"`
	DiscoveredAt time.Time  `json:"discovered_at"`
}

// EntityID implements Entity.
func (u *Username) EntityID() string { return u.ID }

// EntityKind implements Entity.
func (u *Username) EntityKind() NodeKind { return NodeUsername }

// SocialAccount describes a specific platform account of a person or username.
type SocialAccount struct {
	ID           string     `json:"id"`
	Platform     string     `json:"platform"`
	Handle       string     `json:"handle"`
	URL          string     `json:"url,omitempty"`
	State        State      `json:"state"`
	Confidence   Confidence `json:"confidence,omitempty"`
	Sources      []string   `json:"sources,omitempty"`
	DiscoveredAt time.Time  `json:"discovered_at"`
}

// EntityID implements Entity.
func (s *SocialAccount) EntityID() string { return s.ID }

// EntityKind implements Entity.
func (s *SocialAccount) EntityKind() NodeKind { return NodeSocialAccount }

// Repository describes a public code repository observed in open sources.
type Repository struct {
	ID           string     `json:"id"`
	Owner        string     `json:"owner"`
	Name         string     `json:"name"`
	URL          string     `json:"url,omitempty"`
	Description  string     `json:"description,omitempty"`
	Stars        int        `json:"stars,omitempty"`
	State        State      `json:"state"`
	Confidence   Confidence `json:"confidence,omitempty"`
	Sources      []string   `json:"sources,omitempty"`
	DiscoveredAt time.Time  `json:"discovered_at"`
}

// EntityID implements Entity.
func (r *Repository) EntityID() string { return r.ID }

// EntityKind implements Entity.
func (r *Repository) EntityKind() NodeKind { return NodeRepository }

// Certificate describes an X.509 certificate observed in certificate logs
// (e.g. crt.sh).
type Certificate struct {
	ID           string     `json:"id"`
	CommonName   string     `json:"common_name"`
	DNSNames     []string   `json:"dns_names,omitempty"`
	Issuer       string     `json:"issuer,omitempty"`
	Serial       string     `json:"serial,omitempty"`
	NotBefore    *time.Time `json:"not_before,omitempty"`
	NotAfter     *time.Time `json:"not_after,omitempty"`
	State        State      `json:"state"`
	Confidence   Confidence `json:"confidence,omitempty"`
	Sources      []string   `json:"sources,omitempty"`
	DiscoveredAt time.Time  `json:"discovered_at"`
}

// EntityID implements Entity.
func (c *Certificate) EntityID() string { return c.ID }

// EntityKind implements Entity.
func (c *Certificate) EntityKind() NodeKind { return NodeCertificate }

// ASN describes an autonomous system number observed in open sources.
type ASN struct {
	ID           string     `json:"id"`
	Number       int        `json:"number"`
	Name         string     `json:"name,omitempty"`
	CIDRs        []string   `json:"cidrs,omitempty"`
	State        State      `json:"state"`
	Confidence   Confidence `json:"confidence,omitempty"`
	Sources      []string   `json:"sources,omitempty"`
	DiscoveredAt time.Time  `json:"discovered_at"`
}

// EntityID implements Entity.
func (a *ASN) EntityID() string { return a.ID }

// EntityKind implements Entity.
func (a *ASN) EntityKind() NodeKind { return NodeASN }
