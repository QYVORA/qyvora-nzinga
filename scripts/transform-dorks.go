// transform-dorks.go is a one-time data transformation script that parses
// WhatsMyName and Sherlock JSON data files and transforms them into Nzinga's
// dork template schema. This is a standalone script, not part of the shipped
// binary.
//
// Usage:
//   go run scripts/transform-dorks.go
//
// Input:
//   - ~/nzinga-datasrc/WhatsMyName/wmn-data.json
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
// The script merges WhatsMyName and Sherlock site data, deduplicates by domain,
// and converts each site into a direct profile-check dork template (not a
// Google search dork, but a direct URL pattern).

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

// WhatsMyNameData is the structure of wmn-data.json.
type WhatsMyNameData struct {
	Sites []struct {
		Name     string   `json:"name"`
		URICheck string   `json:"uri_check"`
		Category string   `json:"cat,omitempty"`
		Known    []string `json:"known,omitempty"`
	} `json:"sites"`
}

// SherlockData is the structure of Sherlock's data.json (map of site name to config).
type SherlockData map[string]struct {
	URL      string      `json:"url"`
	URLMain  string      `json:"urlMain"`
	ErrorMsg interface{} `json:"errorMsg,omitempty"` // Can be string or array
	IsNSFW   bool        `json:"isNSFW,omitempty"`
}

// SiteEntry represents a merged site entry from both sources.
type SiteEntry struct {
	Name   string
	URL    string
	Domain string
	Source string // "whatsmyname", "sherlock", "both"
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

	// Load data files.
	wmnPath := filepath.Join(homeDir, "nzinga-datasrc", "WhatsMyName", "wmn-data.json")
	sherlockPath := filepath.Join(homeDir, "nzinga-datasrc", "sherlock", "sherlock_project", "resources", "data.json")

	wmnSites, err := loadWhatsMyName(wmnPath)
	if err != nil {
		return fmt.Errorf("loading WhatsMyName: %w", err)
	}
	fmt.Printf("Loaded %d WhatsMyName sites\n", len(wmnSites))

	sherlockSites, err := loadSherlock(sherlockPath)
	if err != nil {
		return fmt.Errorf("loading Sherlock: %w", err)
	}
	fmt.Printf("Loaded %d Sherlock sites\n", len(sherlockSites))

	// Merge and deduplicate by domain.
	merged := mergeSites(wmnSites, sherlockSites)
	fmt.Printf("Merged to %d unique sites (by domain)\n", len(merged))

	// Filter out NSFW sites.
	filtered := filterNSFW(merged)
	fmt.Printf("Filtered to %d sites (removed NSFW)\n", len(filtered))

	// Convert to dork templates.
	templates := convertToDorks(filtered)
	fmt.Printf("Generated %d dork templates\n", len(templates))

	// Add infrastructure dorks (manually curated based on common GHDB patterns).
	infraDorks := generateInfraDorks()
	fmt.Printf("Generated %d infrastructure dorks\n", len(infraDorks))

	// Write output files.
	outDir := "internal/search/dorks"
	if err := os.MkdirAll(filepath.Join(outDir, "human"), 0755); err != nil {
		return fmt.Errorf("creating human dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(outDir, "infra"), 0755); err != nil {
		return fmt.Errorf("creating infra dir: %w", err)
	}

	// Split username templates by category.
	usernameTemplates := filterByCategory(templates, "username")
	if err := writeYAML(filepath.Join(outDir, "human", "username.yaml"), usernameTemplates); err != nil {
		return err
	}
	fmt.Printf("Wrote %d templates to human/username.yaml\n", len(usernameTemplates))

	// Write infrastructure dorks.
	if err := writeInfraDorks(outDir, infraDorks); err != nil {
		return err
	}

	// Write placeholder files for other human categories.
	if err := writePlaceholderHumanFiles(outDir); err != nil {
		return err
	}

	fmt.Println("\nTransformation complete!")
	fmt.Println("Output files written to internal/search/dorks/human/ and internal/search/dorks/infra/")
	return nil
}

func loadWhatsMyName(path string) ([]SiteEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var wmn WhatsMyNameData
	if err := json.Unmarshal(data, &wmn); err != nil {
		return nil, err
	}

	var sites []SiteEntry
	for _, site := range wmn.Sites {
		if site.URICheck == "" {
			continue
		}
		domain := extractDomain(site.URICheck)
		if domain == "" {
			continue
		}
		// Replace {account} placeholder with {target} for Nzinga.
		templateURL := strings.ReplaceAll(site.URICheck, "{account}", "{target}")
		sites = append(sites, SiteEntry{
			Name:   site.Name,
			URL:    templateURL,
			Domain: domain,
			Source: "whatsmyname",
		})
	}
	return sites, nil
}

// SherlockSiteConfig represents one site entry in Sherlock's data.
type SherlockSiteConfig struct {
	URL      string      `json:"url"`
	URLMain  string      `json:"urlMain"`
	ErrorMsg interface{} `json:"errorMsg,omitempty"` // Can be string or array
	IsNSFW   bool        `json:"isNSFW,omitempty"`
}

func loadSherlock(path string) ([]SiteEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Parse as raw map first to handle the $schema string value.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	var sites []SiteEntry
	for name, configBytes := range raw {
		// Skip the $schema key.
		if name == "$schema" {
			continue
		}

		var config SherlockSiteConfig
		if err := json.Unmarshal(configBytes, &config); err != nil {
			// Skip entries that don't match the site config structure.
			continue
		}

		if config.URL == "" || config.IsNSFW {
			continue
		}
		domain := extractDomain(config.URL)
		if domain == "" {
			continue
		}
		// Replace {} placeholder with {target} for Nzinga.
		templateURL := strings.ReplaceAll(config.URL, "{}", "{target}")
		sites = append(sites, SiteEntry{
			Name:   name,
			URL:    templateURL,
			Domain: domain,
			Source: "sherlock",
		})
	}
	return sites, nil
}

func mergeSites(wmn, sherlock []SiteEntry) []SiteEntry {
	// Deduplicate by domain, preferring WhatsMyName when there's overlap.
	byDomain := make(map[string]SiteEntry)
	for _, site := range wmn {
		byDomain[site.Domain] = site
	}
	for _, site := range sherlock {
		if existing, found := byDomain[site.Domain]; found {
			// Mark as coming from both sources.
			existing.Source = "both"
			byDomain[site.Domain] = existing
		} else {
			byDomain[site.Domain] = site
		}
	}

	var result []SiteEntry
	for _, site := range byDomain {
		result = append(result, site)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Domain < result[j].Domain
	})
	return result
}

func filterNSFW(sites []SiteEntry) []SiteEntry {
	// Already filtered during load, but double-check domain patterns.
	var filtered []SiteEntry
	nsfwPatterns := []string{"onlyfans", "admireme", "allthingsworn", "fansly"}
	for _, site := range sites {
		nsfw := false
		for _, pattern := range nsfwPatterns {
			if strings.Contains(strings.ToLower(site.Domain), pattern) {
				nsfw = true
				break
			}
		}
		if !nsfw {
			filtered = append(filtered, site)
		}
	}
	return filtered
}

func convertToDorks(sites []SiteEntry) []DorkTemplate {
	var templates []DorkTemplate
	for _, site := range sites {
		id := "username." + sanitizeID(site.Domain)
		templates = append(templates, DorkTemplate{
			ID:          id,
			Category:    "username",
			Name:        site.Name + " profile check",
			Description: fmt.Sprintf("Direct profile URL check for %s", site.Name),
			Query:       site.URL,
			Tags:        []string{"direct-check", "profile"},
		})
	}
	return templates
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

func filterByCategory(templates []DorkTemplate, category string) []DorkTemplate {
	var filtered []DorkTemplate
	for _, t := range templates {
		if t.Category == category {
			filtered = append(filtered, t)
		}
	}
	return filtered
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
	// Strip www. prefix for deduplication.
	host = strings.TrimPrefix(host, "www.")
	return host
}

var idSanitizeRE = regexp.MustCompile(`[^a-z0-9._-]+`)

func sanitizeID(domain string) string {
	// Convert domain to a valid dork ID: lowercase, replace invalid chars with hyphen.
	id := strings.ToLower(domain)
	id = strings.ReplaceAll(id, ".", "-")
	id = idSanitizeRE.ReplaceAllString(id, "-")
	id = strings.Trim(id, "-")
	return id
}
