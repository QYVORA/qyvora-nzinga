// Package normalization converts raw source observations into normalized
// entities, relationship edges, and evidence inside the session. It is where
// the observation vocabulary (source "key" conventions) becomes typed model
// values. Normalization never fabricates: values that cannot be typed are
// kept as observations only.
package normalization

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-nzinga/internal/events"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// Normalizer types observations into the session model.
type Normalizer struct {
	sess   *models.Session
	events *events.Stream
}

// New returns a Normalizer bound to a session and event stream.
func New(sess *models.Session, ev *events.Stream) *Normalizer {
	if sess.Attributes == nil {
		sess.Attributes = map[string]string{}
	}
	return &Normalizer{sess: sess, events: ev}
}

// Normalize processes observations in order, upserting entities and edges
// and recording evidence. The session's deduplication keeps the run stable.
func (n *Normalizer) Normalize(ctx context.Context, observations []*models.Observation) {
	for _, o := range observations {
		if o == nil {
			continue
		}
		o.ID = models.NewID("obs")
		n.apply(o)
		n.sess.AddObservation(o)
		n.addEvidence(o)
		if n.events != nil {
			n.events.Info(events.ObservationCollected, map[string]any{
				"source": o.Source, "key": o.Key, "value": o.Value, "target": o.Target,
			})
		}
	}
}

// Evidence returns the evidence items created from the processed observations.
func (n *Normalizer) Evidence() []*models.Evidence { return n.sess.Evidence }

func (n *Normalizer) addEvidence(o *models.Observation) {
	ev := &models.Evidence{
		ID:           models.NewID("ev"),
		Kind:         models.EvidenceObservation,
		Source:       o.Source,
		SourceID:     o.SourceID,
		SourceType:   o.SourceType,
		Target:       o.Target,
		Data:         fmt.Sprintf("%s=%s", o.Key, o.Value),
		Hash:         models.HashContent(o.Source + "\x00" + o.Target + "\x00" + o.Key + "\x00" + o.Value),
		RawReference: o.RawReference,
		State:        o.State,
		ObservedAt:   o.ObservedAt,
		CollectedAt:  o.CollectedAt,
		Timestamp:    o.Timestamp,
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	n.sess.AddEvidence(ev)
}

func (n *Normalizer) apply(o *models.Observation) {
	switch o.Key {
	case "domain":
		n.upsertDomain(o.Value, o.Source, models.StateObserved, models.ConfidenceObserved)
	case "hostname":
		n.handleHostname(o)
	case "ip":
		n.upsertIP(o.Value, o.Source)
	case "a", "aaaa":
		ip := n.upsertIP(o.Value, o.Source)
		host := n.hostnameEntity(o.Target)
		if host == nil && isHostnameLike(o.Target) && apexDomainOf(o.Target) != o.Target {
			// The record may be processed before the hostname observation that
			// introduced it; create a minimal entity so the resolution edge is
			// still recorded and order-independent. Apex domains never become
			// hostname entities.
			host = n.upsertHostname(o.Target, "", o.Source, models.StateInferred, models.ConfidencePossible)
		}
		if host != nil {
			n.relate(host.ID, ip.ID, models.RelResolvesTo, o.Source, o)
		}
	case "cname":
		target := n.upsertHostname(o.Value, "", o.Source, models.StateInferred, models.ConfidencePossible)
		if src := n.hostnameEntity(o.Target); src != nil {
			n.relate(src.ID, target.ID, models.RelRelated, o.Source, o)
		}
	case "nameserver", "mx":
		ns := n.upsertHostname(o.Value, "", o.Source, models.StateInferred, models.ConfidencePossible)
		if zone := n.domainEntity(o.Target); zone != nil {
			n.relate(zone.ID, ns.ID, models.RelUses, o.Source, o)
		}
	case "txt":
		n.setAttribute("txt."+o.Target, o.Value)
	case "email":
		em := n.upsertEmail(o.Value, o.Source)
		if o.Target != "" {
			if host := n.usernameByHandle(o.Target); host != nil {
				n.relate(em.ID, host.ID, models.RelOwes, o.Source, o)
			} else if d := n.domainEntity(o.Target); d != nil {
				n.relate(em.ID, d.ID, models.RelOwes, o.Source, o)
			}
		}
	case "registrant":
		org := n.upsertOrg(o.Value, o.Source)
		if d := n.domainEntity(o.Target); d != nil {
			n.relate(org.ID, d.ID, models.RelRegisters, o.Source, o)
		}
	case "username":
		u := n.upsertUsername(o.Value, o.Source)
		if o.Target != "" && !contains(u.Platforms, o.Target) {
			u.Platforms = append(u.Platforms, o.Target)
		}
		if url, ok := o.Raw["url"]; ok {
			sa := n.upsertSocialAccount(o.Target, o.Value, url, o.Source)
			n.relate(u.ID, sa.ID, models.RelOwes, o.Source, o)
		}
	case "social_url":
		platform := o.Raw["platform"]
		if platform == "" {
			platform = "web"
		}
		sa := n.upsertSocialAccount(platform, o.Target, o.Value, o.Source)
		if u := n.usernameByHandle(o.Target); u != nil {
			n.relate(u.ID, sa.ID, models.RelOwes, o.Source, o)
		}
	case "person_name":
		p := n.upsertPerson(o.Value, o.Source)
		if u := n.usernameByHandle(o.Target); u != nil {
			n.relate(u.ID, p.ID, models.RelOwes, o.Source, o)
		}
	case "github_company":
		org := n.upsertOrg(o.Value, o.Source)
		if u := n.usernameByHandle(o.Target); u != nil {
			n.relate(u.ID, org.ID, models.RelRelated, o.Source, o)
		}
	case "repo":
		owner, repoName := splitRepo(o.Value)
		if owner == "" || repoName == "" {
			return
		}
		repo := n.upsertRepo(owner, repoName, o.Source)
		if stars, err := strconv.Atoi(o.Raw["stars"]); err == nil {
			repo.Stars = stars
		}
		if url := o.Raw["url"]; url != "" {
			repo.URL = url
		}
		if desc := o.Raw["description"]; desc != "" {
			repo.Description = desc
		}
		ownerEntity := n.ownerEntity(owner)
		if ownerEntity != "" {
			n.relate(ownerEntity, repo.ID, models.RelOwns, o.Source, o)
		}
	case "cert":
		cert := n.upsertCert(o.Value, o.Source)
		if raw := o.Raw; raw != nil {
			if v := raw["issuer"]; v != "" {
				cert.Issuer = v
			}
			if v := raw["serial"]; v != "" {
				cert.Serial = v
			}
		}
		if d := n.domainEntity(o.Target); d != nil {
			n.relate(d.ID, cert.ID, models.RelUses, o.Source, o)
		}
	case "dns.wildcard":
		if strings.EqualFold(o.Value, "true") {
			n.setAttribute("dns.wildcard", "true")
		}
	case "asn":
		num, err := strconv.Atoi(o.Value)
		if err != nil {
			return
		}
		asn := n.upsertASN(num, o.Source)
		if v := o.Raw["owner"]; v != "" {
			asn.Name = v
		}
		if ip := n.ipEntity(o.Target); ip != nil {
			n.relate(asn.ID, ip.ID, models.RelControls, o.Source, o)
		}
	case "owned_domain":
		d := n.upsertDomain(o.Value, o.Source, models.StateInferred, models.ConfidencePossible)
		if org := n.orgByName(o.Target); org != nil {
			n.relate(org.ID, d.ID, models.RelOwns, o.Source, o)
		}
	case "organization":
		n.upsertOrg(o.Value, o.Source)
	case "github_org":
		n.upsertOrg(o.Value, o.Source)
	}
}

func (n *Normalizer) handleHostname(o *models.Observation) {
	h := n.upsertHostname(o.Value, "", o.Source, models.StateObserved, models.ConfidenceObserved)
	// Attribute ownership to the observation's target domain only when the
	// hostname actually falls under it. A SAN like mail.example.net seen while
	// querying example.com belongs to example.net, not example.com, so it must
	// not be attributed to the queried zone.
	if o.Target != "" && o.Target != o.Value && within(o.Value, o.Target) {
		if d := n.domainEntity(o.Target); d != nil {
			n.relate(h.ID, d.ID, models.RelOwes, o.Source, o)
		}
	}
	// Infer the owner domain from the hostname itself when none was given or
	// when the attribution above did not apply.
	if d := apexDomainOf(o.Value); d != "" && n.domainEntity(d) == nil {
		dd := n.upsertDomain(d, o.Source, models.StateInferred, models.ConfidencePossible)
		n.relate(h.ID, dd.ID, models.RelOwes, o.Source, o)
	}
}

// within reports whether host is equal to or a subdomain of zone.
func within(host, zone string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if zone == "" {
		return false
	}
	if host == zone {
		return true
	}
	return strings.HasSuffix(host, "."+zone)
}

func (n *Normalizer) setAttribute(key, value string) {
	if n.sess.Attributes == nil {
		n.sess.Attributes = map[string]string{}
	}
	if _, ok := n.sess.Attributes[key]; !ok {
		n.sess.Attributes[key] = value
	}
}

func (n *Normalizer) relate(from, to string, typ models.RelationshipType, src string, o *models.Observation) {
	n.sess.AddEdge(&models.Edge{
		ID:         models.NewID("edge"),
		From:       from,
		To:         to,
		Type:       typ,
		Source:     src,
		Confidence: o.Confidence,
		Timestamp:  time.Now().UTC(),
	})
}

func (n *Normalizer) emitDiscovered(verb string, id, label string) {
	if n.events != nil {
		n.events.Info(verb, map[string]any{"id": id, "label": label})
	}
}

// --- entity upserts -------------------------------------------------------

func (n *Normalizer) upsertDomain(name, source string, state models.State, conf models.Confidence) *models.Domain {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return nil
	}
	for _, d := range n.sess.Domains {
		if d != nil && d.Name == name {
			appendSource(&d.Sources, source)
			return d
		}
	}
	d := &models.Domain{
		ID:           models.NewID("dom"),
		Name:         name,
		State:        state,
		Confidence:   conf,
		Sources:      []string{source},
		DiscoveredAt: time.Now().UTC(),
	}
	n.sess.Domains = append(n.sess.Domains, d)
	n.emitDiscovered(events.DomainDiscovered, d.ID, d.Name)
	return d
}

func (n *Normalizer) hostnameEntity(name string) *models.Hostname {
	return n.findHostname(name)
}

func (n *Normalizer) upsertHostname(fqdn, parent, source string, state models.State, conf models.Confidence) *models.Hostname {
	fqdn = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	if fqdn == "" {
		return nil
	}
	if h := n.findHostname(fqdn); h != nil {
		appendSource(&h.Sources, source)
		return h
	}
	h := &models.Hostname{
		ID:           models.NewID("hst"),
		FQDN:         fqdn,
		State:        state,
		Confidence:   conf,
		Sources:      []string{source},
		DiscoveredAt: time.Now().UTC(),
	}
	if parent != "" {
		h.Domain = parent
	}
	n.sess.Hostnames = append(n.sess.Hostnames, h)
	n.emitDiscovered(events.HostnameDiscovered, h.ID, h.FQDN)
	return h
}

func (n *Normalizer) findHostname(fqdn string) *models.Hostname {
	for _, h := range n.sess.Hostnames {
		if h != nil && strings.EqualFold(h.FQDN, fqdn) {
			return h
		}
	}
	return nil
}

func (n *Normalizer) upsertIP(addr, source string) *models.IP {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	for _, ip := range n.sess.IPs {
		if ip != nil && ip.Address == addr {
			appendSource(&ip.Sources, source)
			return ip
		}
	}
	ip := &models.IP{
		ID:           models.NewID("ip"),
		Address:      addr,
		Version:      4,
		State:        models.StateObserved,
		Confidence:   models.ConfidenceObserved,
		Sources:      []string{source},
		DiscoveredAt: time.Now().UTC(),
	}
	if strings.Contains(addr, ":") {
		ip.Version = 6
	}
	n.sess.IPs = append(n.sess.IPs, ip)
	n.emitDiscovered(events.IPDiscovered, ip.ID, ip.Address)
	return ip
}

func (n *Normalizer) ipEntity(addr string) *models.IP {
	for _, ip := range n.sess.IPs {
		if ip != nil && ip.Address == addr {
			return ip
		}
	}
	return nil
}

func (n *Normalizer) upsertEmail(addr, source string) *models.Email {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" || !strings.Contains(addr, "@") {
		return nil
	}
	for _, e := range n.sess.Emails {
		if e != nil && e.Address == addr {
			appendSource(&e.Sources, source)
			return e
		}
	}
	parts := strings.SplitN(addr, "@", 2)
	e := &models.Email{
		ID:           models.NewID("eml"),
		Address:      addr,
		Local:        parts[0],
		Domain:       parts[1],
		State:        models.StateObserved,
		Confidence:   models.ConfidenceObserved,
		Sources:      []string{source},
		DiscoveredAt: time.Now().UTC(),
	}
	n.sess.Emails = append(n.sess.Emails, e)
	n.emitDiscovered(events.EmailDiscovered, e.ID, e.Address)
	return e
}

func (n *Normalizer) upsertUsername(handle, source string) *models.Username {
	handle = strings.ToLower(strings.TrimSpace(handle))
	if handle == "" {
		return nil
	}
	for _, u := range n.sess.Usernames {
		if u != nil && u.Handle == handle {
			appendSource(&u.Sources, source)
			return u
		}
	}
	u := &models.Username{
		ID:           models.NewID("usr"),
		Handle:       handle,
		State:        models.StateObserved,
		Confidence:   models.ConfidenceObserved,
		Sources:      []string{source},
		DiscoveredAt: time.Now().UTC(),
	}
	n.sess.Usernames = append(n.sess.Usernames, u)
	n.emitDiscovered(events.UsernameDiscovered, u.ID, u.Handle)
	return u
}

func (n *Normalizer) usernameByHandle(handle string) *models.Username {
	if handle == "" {
		return nil
	}
	for _, u := range n.sess.Usernames {
		if u != nil && strings.EqualFold(u.Handle, handle) {
			return u
		}
	}
	return nil
}

func (n *Normalizer) upsertPerson(name, source string) *models.Person {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	for _, p := range n.sess.People {
		if p != nil && strings.EqualFold(p.Name, name) {
			appendSource(&p.Sources, source)
			return p
		}
	}
	p := &models.Person{
		ID:           models.NewID("per"),
		Name:         name,
		State:        models.StateObserved,
		Confidence:   models.ConfidenceObserved,
		Sources:      []string{source},
		DiscoveredAt: time.Now().UTC(),
	}
	n.sess.People = append(n.sess.People, p)
	return p
}

func (n *Normalizer) upsertOrg(name, source string) *models.Organization {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	for _, o := range n.sess.Organizations {
		if o != nil && strings.EqualFold(o.Name, name) {
			appendSource(&o.Sources, source)
			return o
		}
	}
	o := &models.Organization{
		ID:           models.NewID("org"),
		Name:         name,
		State:        models.StateObserved,
		Confidence:   models.ConfidenceObserved,
		Sources:      []string{source},
		DiscoveredAt: time.Now().UTC(),
	}
	n.sess.Organizations = append(n.sess.Organizations, o)
	return o
}

func (n *Normalizer) orgByName(name string) *models.Organization {
	if name == "" {
		return nil
	}
	for _, o := range n.sess.Organizations {
		if o != nil && strings.EqualFold(o.Name, name) {
			return o
		}
	}
	return nil
}

func (n *Normalizer) upsertRepo(owner, name, source string) *models.Repository {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	for _, r := range n.sess.Repositories {
		if r != nil && strings.EqualFold(r.Owner, owner) && strings.EqualFold(r.Name, name) {
			appendSource(&r.Sources, source)
			return r
		}
	}
	r := &models.Repository{
		ID:           models.NewID("repo"),
		Owner:        owner,
		Name:         name,
		State:        models.StateObserved,
		Confidence:   models.ConfidenceObserved,
		Sources:      []string{source},
		DiscoveredAt: time.Now().UTC(),
	}
	n.sess.Repositories = append(n.sess.Repositories, r)
	return r
}

func (n *Normalizer) ownerEntity(owner string) string {
	owner = strings.ToLower(strings.TrimSpace(owner))
	if owner == "" {
		return ""
	}
	for _, u := range n.sess.Usernames {
		if u != nil && u.Handle == owner {
			return u.ID
		}
	}
	for _, o := range n.sess.Organizations {
		if o != nil && strings.EqualFold(o.Name, owner) {
			return o.ID
		}
	}
	// No known entity owns it; create an inferred username placeholder so the
	// ownership edge stays truthful (the owner may be unobserved).
	u := n.upsertUsername(owner, "simulation")
	u.State = models.StateInferred
	u.Confidence = models.ConfidencePossible
	return u.ID
}

func (n *Normalizer) upsertCert(commonName, source string) *models.Certificate {
	commonName = strings.TrimSpace(commonName)
	if commonName == "" {
		return nil
	}
	for _, c := range n.sess.Certificates {
		if c != nil && c.CommonName == commonName {
			appendSource(&c.Sources, source)
			return c
		}
	}
	c := &models.Certificate{
		ID:           models.NewID("cert"),
		CommonName:   commonName,
		State:        models.StateObserved,
		Confidence:   models.ConfidenceObserved,
		Sources:      []string{source},
		DiscoveredAt: time.Now().UTC(),
	}
	n.sess.Certificates = append(n.sess.Certificates, c)
	return c
}

func (n *Normalizer) upsertASN(num int, source string) *models.ASN {
	for _, a := range n.sess.ASNs {
		if a != nil && a.Number == num {
			appendSource(&a.Sources, source)
			return a
		}
	}
	a := &models.ASN{
		ID:           models.NewID("asn"),
		Number:       num,
		State:        models.StateObserved,
		Confidence:   models.ConfidenceObserved,
		Sources:      []string{source},
		DiscoveredAt: time.Now().UTC(),
	}
	n.sess.ASNs = append(n.sess.ASNs, a)
	return a
}

func (n *Normalizer) upsertSocialAccount(platform, handle, url, source string) *models.SocialAccount {
	platform = strings.ToLower(strings.TrimSpace(platform))
	handle = strings.ToLower(strings.TrimSpace(handle))
	if platform == "" || handle == "" {
		return nil
	}
	for _, sa := range n.sess.SocialAccounts {
		if sa != nil && strings.EqualFold(sa.Platform, platform) && strings.EqualFold(sa.Handle, handle) {
			if url != "" && sa.URL == "" {
				sa.URL = url
			}
			appendSource(&sa.Sources, source)
			return sa
		}
	}
	sa := &models.SocialAccount{
		ID:           models.NewID("sa"),
		Platform:     platform,
		Handle:       handle,
		URL:          url,
		State:        models.StateObserved,
		Confidence:   models.ConfidenceObserved,
		Sources:      []string{source},
		DiscoveredAt: time.Now().UTC(),
	}
	n.sess.SocialAccounts = append(n.sess.SocialAccounts, sa)
	return sa
}

func (n *Normalizer) domainEntity(name string) *models.Domain {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return nil
	}
	for _, d := range n.sess.Domains {
		if d != nil && d.Name == name {
			return d
		}
	}
	return nil
}

// --- helpers --------------------------------------------------------------

func appendSource(list *[]string, source string) {
	if source == "" {
		return
	}
	for _, s := range *list {
		if s == source {
			return
		}
	}
	*list = append(*list, source)
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func splitRepo(value string) (string, string) {
	parts := strings.SplitN(value, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func isHostnameLike(s string) bool {
	return strings.Contains(s, ".") && !strings.Contains(s, "@")
}

// apexDomainOf extracts the registrable-ish owner domain from a hostname.
// The heuristic takes the last two labels for common two-part TLDs and the
// last two otherwise; it is honest (the result is an inferred domain) and is
// enough for demo granularity.
func apexDomainOf(host string) string {
	host = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(host)), ".")
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return ""
	}
	if len(labels) == 2 {
		return host
	}
	tld := labels[len(labels)-1]
	if tld == "com" || tld == "net" || tld == "org" || tld == "io" ||
		tld == "co" || tld == "gov" || tld == "edu" || len(tld) == 2 {
		if len(labels) >= 3 {
			return strings.Join(labels[len(labels)-2:], ".")
		}
	}
	return strings.Join(labels[len(labels)-2:], ".")
}
