// Package relationships materializes the entity/edge graph from a session.
// Shaka's Active Directory model is already a graph; in the OSINT model the
// graph is built here by turning every normalized entity into a node (using
// the entity identifier, so edges align) and emitting the collected edges.
package relationships

import (
	"sort"
	"strconv"
	"time"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// Build materializes session entities as graph nodes. Edge set is already
// populated by normalization; nodes are synthesized deterministically.
func Build(sess *models.Session) {
	if sess == nil {
		return
	}
	nodes := []*models.Node{}

	add := func(kind models.NodeKind, id, label, source string) {
		nodes = append(nodes, &models.Node{
			ID:        id,
			Kind:      kind,
			Label:     label,
			Source:    source,
			CreatedAt: time.Now().UTC(),
		})
	}

	for _, d := range sess.Domains {
		if d != nil {
			add(models.NodeDomain, d.ID, d.Name, firstSource(d.Sources))
		}
	}
	for _, h := range sess.Hostnames {
		if h != nil {
			add(models.NodeHostname, h.ID, h.FQDN, firstSource(h.Sources))
		}
	}
	for _, ip := range sess.IPs {
		if ip != nil {
			add(models.NodeIP, ip.ID, ip.Address, firstSource(ip.Sources))
		}
	}
	for _, o := range sess.Organizations {
		if o != nil {
			add(models.NodeOrganization, o.ID, o.Name, firstSource(o.Sources))
		}
	}
	for _, p := range sess.People {
		if p != nil {
			add(models.NodePerson, p.ID, p.Name, firstSource(p.Sources))
		}
	}
	for _, e := range sess.Emails {
		if e != nil {
			add(models.NodeEmail, e.ID, e.Address, firstSource(e.Sources))
		}
	}
	for _, u := range sess.Usernames {
		if u != nil {
			add(models.NodeUsername, u.ID, u.Handle, firstSource(u.Sources))
		}
	}
	for _, sa := range sess.SocialAccounts {
		if sa != nil {
			add(models.NodeSocialAccount, sa.ID, sa.Platform+"/"+sa.Handle, firstSource(sa.Sources))
		}
	}
	for _, r := range sess.Repositories {
		if r != nil {
			add(models.NodeRepository, r.ID, r.Owner+"/"+r.Name, firstSource(r.Sources))
		}
	}
	for _, c := range sess.Certificates {
		if c != nil {
			add(models.NodeCertificate, c.ID, c.CommonName, firstSource(c.Sources))
		}
	}
	for _, a := range sess.ASNs {
		if a != nil {
			add(models.NodeASN, a.ID, strconv.Itoa(a.Number), firstSource(a.Sources))
		}
	}

	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Kind != nodes[j].Kind {
			return nodes[i].Kind < nodes[j].Kind
		}
		return nodes[i].Label < nodes[j].Label
	})
	sess.Nodes = nodes
}

func firstSource(sources []string) string {
	if len(sources) == 0 {
		return ""
	}
	return sources[0]
}
