// transform-dorks.go is a one-time data transformation script that parses
// Sherlock's username-check data.json and converts each profile check into a
// search-engine dork template. This is a standalone script, not part of the
// shipped binary.
//
// Usage:
//   go run scripts/transform-dorks.go
//
// Input:
//   - ~/nzinga-datasrc/sherlock/sherlock_project/resources/data.json
//
// Output:
//   - internal/search/dorks/human/username.yaml
//   - internal/search/dorks/human/name.yaml
//   - internal/search/dorks/human/email.yaml
//   - internal/search/dorks/infra/exposed_docs.yaml
//   - internal/search/dorks/infra/login_panels.yaml
//   - internal/search/dorks/infra/subdomains.yaml
//
// Sherlock is MIT-licensed, so the transformed catalogue is redistributable
// under Nzinga's own licence with attribution. The catalogue is deliberately
// produced from this single source: a profile-URL check is not itself a search
// query, and converting a direct HTTPS fetch into a `site:` expression keeps
// every entry expressible through a search provider.

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// DorkTemplate is Nzinga's schema for a dork query template.
type DorkTemplate struct {
	ID          string   `yaml:"id"`
	Category    string   `yaml:"category"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Query       string   `yaml:"query"`
	Tags        []string `yaml:"tags,omitempty"`
}

// SherlockSiteConfig is one entry in Sherlock's data.json (omit the $schema key).
type SherlockSiteConfig struct {
	URL      string      `json:"url"`
	URLMain  string      `json:"urlMain"`
	ErrorMsg interface{} `json:"errorMsg,omitempty"` // Can be string or array
	IsNSFW   bool        `json:"isNSFW,omitempty"`
}

// SiteEntry represents one site read from Sherlock.
type SiteEntry struct {
	Name   string
	URL    string
	Domain string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("getting home dir: %w", err)
	}

	sherlockPath := filepath.Join(homeDir, "nzinga-datasrc", "sherlock", "sherlock_project", "resources", "data.json")
	sites, err := loadSherlock(sherlockPath)
	if err != nil {
		return fmt.Errorf("loading Sherlock: %w", err)
	}
	fmt.Printf("Loaded %d Sherlock sites (%d after NSFW filter)\n", len(sites), len(sites))

	// Deduplicate by domain: two Sherlock entries can name the same site.
	sites = dedupeByDomain(sites)
	fmt.Printf("Deduplicated to %d sites\n", len(sites))

	templates, err := convertToDorks(sites)
	if err != nil {
		return err
	}
	fmt.Printf("Generated %d username search dorks\n", len(templates))

	infraDorks := generateInfraDorks()
	fmt.Printf("Generated %d infrastructure dorks\n", len(infraDorks))

	outDir := "internal/search/dorks"
	if err := os.MkdirAll(filepath.Join(outDir, "human"), 0755); err != nil {
		return fmt.Errorf("creating human dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(outDir, "infra"), 0755); err != nil {
		return fmt.Errorf("creating infra dir: %w", err)
	}

	// Write the username catalogue and the curated placeholders.
	if err := writeYAML(filepath.Join(outDir, "human", "username.yaml"), templates); err != nil {
		return err
	}
	fmt.Printf("Wrote %d templates to human/username.yaml\n", len(templates))

	if err := writeInfraDorks(outDir, infraDorks); err != nil {
		return err
	}
	if err := writePlaceholderHumanFiles(outDir); err != nil {
		return err
	}

	fmt.Println("\nTransformation complete!")
	fmt.Println("Output files written to internal/search/dorks/human/ and internal/search/dorks/infra/")
	return nil
}

func loadSherlock(path string) ([]SiteEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Parse as a raw map first to handle the $schema string value.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	var sites []SiteEntry
	for name, configBytes := range raw {
		if name == "$schema" {
			continue
		}
		var config SherlockSiteConfig
		if err := json.Unmarshal(configBytes, &config); err != nil {
			continue
		}
		if config.URL == "" || config.IsNSFW {
			continue
		}
		domain := extractDomain(config.URL)
		if domain == "" {
			continue
		}
		sites = append(sites, SiteEntry{Name: name, URL: config.URL, Domain: domain})
	}
	return sites, nil
}

func dedupeByDomain(sites []SiteEntry) []SiteEntry {
	sort.Slice(sites, func(i, j int) bool { return sites[i].Domain < sites[j].Domain })
	seen := map[string]bool{}
	var out []SiteEntry
	for _, s := range sites {
		if seen[s.Domain] {
			continue
		}
		seen[s.Domain] = true
		out = append(out, s)
	}
	return out
}

// convertToDorks turns a Sherlock profile check into a `site:` search dork.
// A direct profile URL (https://site/user/jane) is not itself a query a search
// provider can run, so it is converted to a site-scoped expression with an
// inurl prefix when the profile path carries the placeholder.
func convertToDorks(sites []SiteEntry) ([]DorkTemplate, error) {
	var templates []DorkTemplate
	for _, site := range sites {
		query, err := searchDorkFor(site.URL)
		if err != nil {
			fmt.Printf("skipping %q (%s): %v\n", site.Name, site.Domain, err)
			continue
		}
		id := "username." + sanitizeID(site.Domain)
		templates = append(templates, DorkTemplate{
			ID:          id,
			Category:    "username",
			Name:        site.Name + " username search",
			Description: fmt.Sprintf("Search-engine dork for %s profile pages of {target}", site.Name),
			Query:       query,
			Tags:        []string{"search-dork", "profile", "username"},
		})
	}
	// The catalogue must stay deterministic: sort by (category, id).
	sort.Slice(templates, func(i, j int) bool { return templates[i].ID < templates[j].ID })
	return templates, nil
}

// searchDorkFor converts a Sherlock profile URL into a search expression that
// keeps {target} so the dork validator and renderer both accept it.
func searchDorkFor(profile string) (string, error) {
	u, err := url.Parse(profile)
	if err != nil {
		return "", fmt.Errorf("unparsable URL: %v", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return "", fmt.Errorf("non-http scheme %q", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	host = strings.TrimPrefix(host, "www.")
	if host == "" {
		return "", fmt.Errorf("empty host")
	}

	// A placeholder in the host (user.tumblr.com style) scopes the whole site.
	if strings.Contains(host, "{target}") {
		return "site:" + host, nil
	}

	// A placeholder in the path gives a precise inurl prefix.
	if idx := strings.Index(u.Path, "{target}"); idx >= 0 {
		prefix := u.Path[:idx+len("{target}")]
		return `site:` + host + ` inurl:"` + prefix + `"`, nil
	}

	// Otherwise the profile URL parametrises the target in its query string or
	// directly at the root; a bare site-scoped term search still works.
	return `site:` + host + ` "{target}"`, nil
}

func generateInfraDorks() map[string][]DorkTemplate {
	// Manually curated infrastructure dorks based on common GHDB patterns.
	return map[string][]DorkTemplate{
		"exposed_docs": {
			{
				ID:          "infra.docs.pdf",
				Category:    "exposed-docs",
				Name:        "Exposed PDF documents",
				Description: "Find publicly indexed PDF files on the target domain",
				Query:       "site:{target} filetype:pdf",
				Tags:        []string{"documents", "google-dork"},
			},
			{
				ID:          "infra.docs.xlsx",
				Category:    "exposed-docs",
				Name:        "Exposed Excel spreadsheets",
				Description: "Find publicly indexed Excel files on the target domain",
				Query:       "site:{target} filetype:xlsx",
				Tags:        []string{"documents", "google-dork"},
			},
			{
				ID:          "infra.docs.docx",
				Category:    "exposed-docs",
				Name:        "Exposed Word documents",
				Description: "Find publicly indexed Word documents on the target domain",
				Query:       "site:{target} filetype:docx",
				Tags:        []string{"documents", "google-dork"},
			},
			{
				ID:          "infra.docs.backup",
				Category:    "exposed-docs",
				Name:        "Backup files",
				Description: "Find backup archives that may contain sensitive data",
				Query:       "site:{target} (filetype:bak OR filetype:sql OR filetype:zip)",
				Tags:        []string{"backup", "google-dork"},
			},
		},
		"login_panels": {
			{
				ID:          "infra.login.admin",
				Category:    "login-panels",
				Name:        "Admin login pages",
				Description: "Find admin login interfaces on the target domain",
				Query:       "site:{target} inurl:admin",
				Tags:        []string{"admin", "google-dork"},
			},
			{
				ID:          "infra.login.wp",
				Category:    "login-panels",
				Name:        "WordPress login",
				Description: "Find WordPress admin login pages",
				Query:       "site:{target} inurl:wp-admin",
				Tags:        []string{"wordpress", "google-dork"},
			},
			{
				ID:          "infra.login.phpmyadmin",
				Category:    "login-panels",
				Name:        "phpMyAdmin interface",
				Description: "Find phpMyAdmin database management interfaces",
				Query:       "site:{target} inurl:phpmyadmin",
				Tags:        []string{"database", "google-dork"},
			},
			{
				ID:          "infra.login.portal",
				Category:    "login-panels",
				Name:        "Login portals",
				Description: "Find general login and signin pages",
				Query:       "site:{target} (inurl:login OR inurl:signin)",
				Tags:        []string{"login", "google-dork"},
			},
		},
		"subdomains": {
			{
				ID:          "infra.subdomain.enumerate",
				Category:    "subdomains",
				Name:        "Subdomain enumeration",
				Description: "Enumerate indexed subdomains of the target",
				Query:       "site:*.{target}",
				Tags:        []string{"enumeration", "google-dork"},
			},
			{
				ID:          "infra.subdomain.dev",
				Category:    "subdomains",
				Name:        "Development subdomains",
				Description: "Find development and staging environments",
				Query:       "site:{target} (inurl:dev OR inurl:staging OR inurl:test)",
				Tags:        []string{"dev", "google-dork"},
			},
			{
				ID:          "infra.subdomain.api",
				Category:    "subdomains",
				Name:        "API endpoints",
				Description: "Find API subdomains and endpoints",
				Query:       "site:{target} inurl:api",
				Tags:        []string{"api", "google-dork"},
			},
		},
	}
}

func writeInfraDorks(baseDir string, infraDorks map[string][]DorkTemplate) error {
	for filename, templates := range infraDorks {
		path := filepath.Join(baseDir, "infra", filename+".yaml")
		if err := writeYAML(path, templates); err != nil {
			return err
		}
		fmt.Printf("Wrote %d templates to infra/%s.yaml\n", len(templates), filename)
	}
	return nil
}

func writePlaceholderHumanFiles(baseDir string) error {
	placeholders := map[string][]DorkTemplate{
		"name": {
			{
				ID:          "human.name.linkedin",
				Category:    "name",
				Name:        "LinkedIn name search",
				Description: "Search for a person's name on LinkedIn",
				Query:       "site:linkedin.com \"{target}\"",
				Tags:        []string{"google-dork", "person"},
			},
			{
				ID:          "human.name.general",
				Category:    "name",
				Name:        "General name search",
				Description: "Broad web search for a person's name",
				Query:       "\"{target}\"",
				Tags:        []string{"google-dork", "person"},
			},
		},
		"email": {
			{
				ID:          "human.email.general",
				Category:    "email",
				Name:        "Email address search",
				Description: "Search for mentions of an email address",
				Query:       "\"{target}\"",
				Tags:        []string{"google-dork", "email"},
			},
			{
				ID:          "human.email.breach",
				Category:    "email",
				Name:        "Email in paste sites",
				Description: "Search for email in paste/leak sites",
				Query:       "site:pastebin.com \"{target}\"",
				Tags:        []string{"google-dork", "breach"},
			},
		},
		"employer": {
			{
				ID:          "human.employer.linkedin",
				Category:    "employer",
				Name:        "LinkedIn company employees",
				Description: "Find employees of a company on LinkedIn",
				Query:       "site:linkedin.com \"{target}\" employees",
				Tags:        []string{"google-dork", "organization"},
			},
			{
				ID:          "human.employer.about",
				Category:    "employer",
				Name:        "Company about pages",
				Description: "Find about/team pages mentioning the organization",
				Query:       "site:{target} (inurl:about OR inurl:team)",
				Tags:        []string{"google-dork", "organization"},
			},
		},
	}

	for filename, templates := range placeholders {
		path := filepath.Join(baseDir, "human", filename+".yaml")
		if err := writeYAML(path, templates); err != nil {
			return err
		}
		fmt.Printf("Wrote %d templates to human/%s.yaml\n", len(templates), filename)
	}
	return nil
}

func writeYAML(path string, templates []DorkTemplate) error {
	data, err := yaml.Marshal(templates)
	if err != nil {
		return fmt.Errorf("marshaling YAML: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func extractDomain(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	host = strings.TrimPrefix(host, "www.")
	return host
}

var idSanitizeRE = regexp.MustCompile(`[^a-z0-9._-]+`)

func sanitizeID(domain string) string {
	id := strings.ToLower(domain)
	id = strings.ReplaceAll(id, ".", "-")
	id = idSanitizeRE.ReplaceAllString(id, "-")
	id = strings.Trim(id, "-")
	return id
}
