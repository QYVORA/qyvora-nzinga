// Package search implements dork-assisted search collection for nzinga: a
// curated, embedded catalog of dork query templates, a provider abstraction
// (offline simulation and a JSON HTTP API), typed anti-bot/rate-limit
// blocking detection, and deterministic result shaping.
//
// Discipline:
//   - templates are the safe, reviewable input: every template is rejected
//     unless it contains the {target} placeholder and a known category;
//   - results coming back from a search index are unverified snippets; the
//     search source marks them as possible/inferred, never as confirmed;
//   - the framework never attempts CAPTCHA, bot, or anti-automation bypass
//     of any kind; when a provider challenges a client it reports a typed
//     BlockedError that the operator resolves by configuring a sanctioned
//     provider, rate limits, or a different surface.
package search

import (
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Category classifies dork templates and their results.
type Category string

const (
	// CategoryGeneral covers breadth queries: indexed pages, login and admin
	// surfaces, configuration endpoints.
	CategoryGeneral Category = "general"
	// CategoryDocuments targets file-type pivots (pdf, docx, xlsx, ...).
	CategoryDocuments Category = "documents"
	// CategoryExposedServices targets files and endpoints that hint at
	// exposed services or backup artifacts (git stores, SQL dumps, logs).
	CategoryExposedServices Category = "exposed-services"
	// CategoryTechnology targets technology fingerprints (CMS, admin panels).
	CategoryTechnology Category = "technology"
	// CategorySocial targets a name or handle across public platforms.
	CategorySocial Category = "social"
)

// AllCategories lists every category in documentation order.
var AllCategories = []Category{
	CategoryGeneral,
	CategoryDocuments,
	CategoryExposedServices,
	CategoryTechnology,
	CategorySocial,
}

// ParseCategory parses a category name, reporting whether it is known.
func ParseCategory(s string) (Category, bool) {
	for _, c := range AllCategories {
		if string(c) == s {
			return c, true
		}
	}
	return "", false
}

// Dork is one query template mated to a category. Templates are the safe,
// reviewable input to the search source: everything else is derived from them.
type Dork struct {
	ID          string   `yaml:"id" json:"id"`
	Category    Category `yaml:"category" json:"category"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Query       string   `yaml:"query" json:"query"`
	Tags        []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// targetPlaceholder is the substitution point for the collected target.
const targetPlaceholder = "{target}"

var validID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// validate rejects malformed templates so a typo cannot deploy a broken query.
func (d *Dork) validate() error {
	if d == nil {
		return fmt.Errorf("dork is nil")
	}
	if d.ID == "" {
		return fmt.Errorf("dork without id (%q)", d.Name)
	}
	if !validID.MatchString(d.ID) {
		return fmt.Errorf("dork id %q contains invalid characters", d.ID)
	}
	if d.Category == "" || !knownCategory(d.Category) {
		return fmt.Errorf("dork %q has unknown category %q", d.ID, d.Category)
	}
	if strings.TrimSpace(d.Name) == "" {
		return fmt.Errorf("dork %q has no name", d.ID)
	}
	if !strings.Contains(d.Query, targetPlaceholder) {
		return fmt.Errorf("dork %q (%s) must contain {%s}", d.ID, d.Name, "target")
	}
	return nil
}

// Render substitutes the target into the query template. The target never
// appears raw in the template output: it is used as-is because dork operators
// like site: and inurl: expect the literal value.
func (d *Dork) Render(target string) (string, error) {
	if err := d.validate(); err != nil {
		return "", err
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("dork %q: empty target", d.ID)
	}
	return strings.ReplaceAll(d.Query, targetPlaceholder, target), nil
}

// Query is a template mated to a target: the concrete expression a provider
// executes.
type Query struct {
	Dork     Dork
	Query    string
	Category Category
}

func knownCategory(c Category) bool {
	_, ok := ParseCategory(string(c))
	return ok
}

// DorkSet is the loaded, validated template catalog.
type DorkSet struct {
	all        []Dork
	byCategory map[Category][]Dork
}

//go:embed dorks/*.yaml
var dorkFS embed.FS

// LoadEmbedded loads and validates the shipped template catalog.
func LoadEmbedded() (*DorkSet, error) {
	return loadDorkSet(dorkFS, "dorks")
}

// loadDorkSet reads every *.yaml template file, validates the templates, and
// returns the catalog. A single invalid template fails the whole load so the
// shipped catalog can never silently lose an entry.
func loadDorkSet(fsys embed.FS, dir string) (*DorkSet, error) {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading embedded dorks: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("embedded dorks directory is empty")
	}

	var list []Dork
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		data, err := fsys.ReadFile(dir + "/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", entry.Name(), err)
		}
		var file []Dork
		if err := yaml.Unmarshal(data, &file); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", entry.Name(), err)
		}
		for i := range file {
			d := file[i]
			if d.ID == "" {
				d.ID = strings.TrimSuffix(entry.Name(), ".yaml") + "-" + fmt.Sprintf("%02d", i+1)
			}
			if err := d.validate(); err != nil {
				return nil, fmt.Errorf("dork %s: %w", entry.Name(), err)
			}
			if seen[d.ID] {
				return nil, fmt.Errorf("duplicate dork id %q", d.ID)
			}
			seen[d.ID] = true
			list = append(list, d)
		}
	}

	sortTemplates(list)
	set := &DorkSet{
		all:        list,
		byCategory: map[Category][]Dork{},
	}
	for _, d := range list {
		set.byCategory[d.Category] = append(set.byCategory[d.Category], d)
	}
	return set, nil
}

// All returns every validated template in stable (category, id) order.
func (s *DorkSet) All() []Dork {
	if s == nil {
		return nil
	}
	out := append([]Dork(nil), s.all...)
	return out
}

// Categories returns the categories (with templates) in documentation order.
func (s *DorkSet) Categories() []Category {
	if s == nil {
		return nil
	}
	var out []Category
	for _, c := range AllCategories {
		if len(s.byCategory[c]) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// InCategory returns the templates of one category, in id order.
func (s *DorkSet) InCategory(c Category) []Dork {
	if s == nil {
		return nil
	}
	return append([]Dork(nil), s.byCategory[c]...)
}

// ByID finds a template by id.
func (s *DorkSet) ByID(id string) (Dork, bool) {
	if s == nil {
		return Dork{}, false
	}
	for _, d := range s.all {
		if d.ID == id {
			return d, true
		}
	}
	return Dork{}, false
}

// ForTarget renders every template that matches the category filter against
// the target. An empty categories list means all categories. The result is
// sorted deterministically by (category, dork id).
func (s *DorkSet) ForTarget(target string, categories []string, max int) ([]Query, error) {
	if s == nil {
		return nil, fmt.Errorf("no dork catalog loaded")
	}
	if s.Count() == 0 {
		return nil, fmt.Errorf("dork catalog is empty")
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("empty dork target")
	}

	allowed := map[Category]bool{}
	for _, raw := range categories {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		c, ok := ParseCategory(strings.ToLower(raw))
		if !ok {
			return nil, fmt.Errorf("unknown dork category %q (valid: %s)", raw, strings.Join(categoryNames(), ", "))
		}
		allowed[c] = true
	}
	useAll := len(allowed) == 0

	var out []Query
	for _, c := range AllCategories {
		if !useAll && !allowed[c] {
			continue
		}
		for _, d := range s.byCategory[c] {
			rendered, err := d.Render(target)
			if err != nil {
				continue
			}
			out = append(out, Query{Dork: d, Query: rendered, Category: c})
			if max > 0 && len(out) >= max {
				return out, nil
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no dork queries matched targets %q", strings.Join(categories, ", "))
	}
	return out, nil
}

// Count returns the number of loaded templates.
func (s *DorkSet) Count() int {
	if s == nil {
		return 0
	}
	return len(s.all)
}

func categoryNames() []string {
	out := make([]string, 0, len(AllCategories))
	for _, c := range AllCategories {
		out = append(out, string(c))
	}
	return out
}

// sortTemplates orders templates deterministically by (category, id).
func sortTemplates(list []Dork) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Category != list[j].Category {
			return categoryRank(list[i].Category) < categoryRank(list[j].Category)
		}
		return list[i].ID < list[j].ID
	})
}

func categoryRank(c Category) int {
	for i, known := range AllCategories {
		if known == c {
			return i
		}
	}
	return len(AllCategories)
}
