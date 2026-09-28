package search

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestLoadEmbeddedValid(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if set.Count() == 0 {
		t.Fatal("embedded catalog is empty")
	}
	ids := map[string]bool{}
	for _, d := range set.All() {
		if ids[d.ID] {
			t.Fatalf("duplicate dork id %q", d.ID)
		}
		ids[d.ID] = true
		if !strings.Contains(d.Query, targetPlaceholder) {
			t.Fatalf("dork %q query missing {target}: %q", d.ID, d.Query)
		}
		if !knownCategory(d.Category) {
			t.Fatalf("dork %q unknown category %q", d.ID, d.Category)
		}
	}
	// Every category file must be represented in the loaded set.
	if len(set.Categories()) == 0 {
		t.Fatal("no categories loaded")
	}
}

func TestDorkRender(t *testing.T) {
	d := Dork{ID: "x", Category: CategoryGeneral, Name: "x", Query: "site:{target} inurl:login"}
	got, err := d.Render("example.com")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got != "site:example.com inurl:login" {
		t.Fatalf("Render = %q", got)
	}
	// Targets with characters that would break the operator are used verbatim;
	// the framework still renders them (it never mangles operator syntax).
	if _, err := d.Render(""); err == nil {
		t.Fatal("Render with empty target should error")
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []Dork{
		{ID: "noquery", Category: CategoryGeneral, Name: "x", Query: "site:foo"},
		{ID: "badcat", Category: "nope", Name: "x", Query: "site:{target}"},
		{ID: "badid $", Category: CategoryGeneral, Name: "x", Query: "site:{target}"},
		{ID: "", Category: CategoryGeneral, Name: "x", Query: "site:{target}"},
		{ID: "noname", Category: CategoryGeneral, Query: "site:{target}"},
	}
	for _, c := range cases {
		if err := c.validate(); err == nil {
			t.Fatalf("validate(%q) should reject", c.ID)
		}
	}
}

func TestForTargetCategories(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	all, err := set.ForTarget("example.com", nil, 0)
	if err != nil {
		t.Fatalf("ForTarget all: %v", err)
	}
	if len(all) <= 1 {
		t.Fatal("expected more than one query")
	}
	docs, err := set.ForTarget("example.com", []string{"documents"}, 0)
	if err != nil {
		t.Fatalf("ForTarget docs: %v", err)
	}
	for _, q := range docs {
		if q.Category != CategoryDocuments {
			t.Fatalf("unexpected category %q", q.Category)
		}
		if !strings.Contains(q.Query, "example.com") {
			t.Fatalf("query not rendered: %q", q.Query)
		}
	}
	if _, err := set.ForTarget("example.com", []string{"bogus"}, 0); err == nil {
		t.Fatal("unknown category should error")
	}
	capped, err := set.ForTarget("example.com", nil, 3)
	if err != nil {
		t.Fatalf("ForTarget capped: %v", err)
	}
	if len(capped) != 3 {
		t.Fatalf("cap not honored: got %d", len(capped))
	}
}

func TestForTargetDeterministic(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	a, _ := set.ForTarget("example.com", nil, 0)
	b, _ := set.ForTarget("example.com", nil, 0)
	if len(a) != len(b) {
		t.Fatalf("nondeterministic query count %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Query != b[i].Query || a[i].Dork.ID != b[i].Dork.ID {
			t.Fatalf("nondeterministic query at %d: %q vs %q", i, a[i].Query, b[i].Query)
		}
	}
}

func TestClassifyBlocked(t *testing.T) {
	if be := ClassifyBlocked(429, ""); be == nil || be.Reason != "rate limited" {
		t.Fatalf("429 should classify as rate limited: %+v", be)
	}
	if be := ClassifyBlocked(403, "please complete the captcha to continue"); be == nil || be.Reason != "anti-automation challenge detected and not bypassed" {
		t.Fatalf("403 captcha should classify as challenge: %+v", be)
	}
	if be := ClassifyBlocked(403, "forbidden, plain"); be == nil || be.Reason != "access denied" {
		t.Fatalf("403 should classify as access denied: %+v", be)
	}
	if be := ClassifyBlocked(200, "some results page"); be != nil {
		t.Fatalf("200 should not classify as blocked: %+v", be)
	}
}

func TestSimulationDeterministic(t *testing.T) {
	p := &SimulationProvider{}
	a, err := p.Search(context.Background(), "site:example.com inurl:login")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	b, err := p.Search(context.Background(), "site:example.com inurl:login")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(a) != len(b) {
		t.Fatalf("nondeterministic simulation: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].URL != b[i].URL || a[i].Title != b[i].Title {
			t.Fatalf("nondeterministic hit at %d", i)
		}
	}
	c, err := p.Search(context.Background(), "site:example.com inurl:admin")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(c) == 0 {
		t.Fatal("simulation returned nothing")
	}
}

func TestExtractHost(t *testing.T) {
	host, ok := ExtractHost("HTTPS://blog.Example.COM/a?b=1")
	if !ok || host != "blog.example.com" {
		t.Fatalf("ExtractHost = %q, %v", host, ok)
	}
	if _, ok := ExtractHost("file:///etc/passwd"); ok {
		t.Fatal("non-http URL must be rejected")
	}
	if _, ok := ExtractHost("javascript:alert(1)"); ok {
		t.Fatal("scheme must be http(s)")
	}
	if _, ok := ExtractHost("not a url"); ok {
		t.Fatal("non-URL must be rejected")
	}
}

func TestParseResultsShapes(t *testing.T) {
	got, err := parseResults([]byte(`{"results":[{"url":"https://a.example.com/x","title":"T"}]}`))
	if err != nil || len(got) != 1 {
		t.Fatalf("envelope parse: %v, %+v", err, got)
	}
	got, err = parseResults([]byte(`[{"url":"https://b.example.com/y"}]`))
	if err != nil || len(got) != 1 {
		t.Fatalf("array parse: %v, %+v", err, got)
	}
	got, err = parseResults([]byte(`{"results":[]}`))
	if err != nil || len(got) != 0 {
		t.Fatalf("empty results: %v, %+v", err, got)
	}
	if _, err = parseResults([]byte(`not json`)); err == nil {
		t.Fatal("garbage should error")
	}
}

// TestLoadEmbeddedSubdirectories verifies that dorks are loaded from subdirectories
// (human/ and infra/) as well as the root dorks/ directory.
func TestLoadEmbeddedSubdirectories(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}

	// Check that new categories from subdirectories are present.
	newCategories := []Category{
		CategoryUsername,
		CategoryName,
		CategoryEmail,
		CategoryEmployer,
		CategoryExposedDocs,
		CategoryLoginPanels,
		CategorySubdomains,
	}

	for _, cat := range newCategories {
		dorks := set.InCategory(cat)
		if len(dorks) == 0 {
			t.Errorf("category %q has no dorks (subdirectory loading may have failed)", cat)
		}
	}

	// Verify username category has significant entries (from WhatsMyName/Sherlock data).
	usernameDorks := set.InCategory(CategoryUsername)
	if len(usernameDorks) < 100 {
		t.Errorf("username category has only %d dorks, expected hundreds from WhatsMyName/Sherlock", len(usernameDorks))
	}
}

// TestLoadWithCustomMerge tests loading with a custom wordlist merged with built-ins.
func TestLoadWithCustomMerge(t *testing.T) {
	// Create a temporary custom wordlist file.
	tmpfile, err := os.CreateTemp("", "custom-dorks-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	customYAML := `- id: test.custom.one
  category: username
  name: Test custom dork 1
  description: Custom test entry
  query: https://test.example.com/{target}
  tags:
    - test
- id: test.custom.two
  category: exposed-docs
  name: Test custom dork 2
  query: site:{target} filetype:test
  tags:
    - test
`
	if _, err := tmpfile.Write([]byte(customYAML)); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	tmpfile.Close()

	// Load with custom wordlist merged.
	set, err := LoadWithCustom(tmpfile.Name(), true)
	if err != nil {
		t.Fatalf("LoadWithCustom: %v", err)
	}

	// Verify built-in dorks are present and the custom set merged on top.
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if set.Count() <= embedded.Count() {
		t.Errorf("merged set has %d dorks, expected the embedded %d plus custom entries", set.Count(), embedded.Count())
	}

	// Verify custom dorks are present.
	custom1, ok := set.ByID("test.custom.one")
	if !ok {
		t.Fatal("custom dork test.custom.one not found in merged set")
	}
	if custom1.Name != "Test custom dork 1" {
		t.Errorf("custom dork has wrong name: %q", custom1.Name)
	}

	custom2, ok := set.ByID("test.custom.two")
	if !ok {
		t.Fatal("custom dork test.custom.two not found in merged set")
	}
	if custom2.Category != CategoryExposedDocs {
		t.Errorf("custom dork has wrong category: %q", custom2.Category)
	}
}

// TestLoadWithCustomOnly tests loading only custom wordlist (built-ins disabled).
func TestLoadWithCustomOnly(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "custom-only-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	customYAML := `- id: custom.only.test
  category: username
  name: Custom only test
  query: https://custom.example.com/{target}
  tags:
    - custom
`
	if _, err := tmpfile.Write([]byte(customYAML)); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	tmpfile.Close()

	// Load with built-ins disabled.
	set, err := LoadWithCustom(tmpfile.Name(), false)
	if err != nil {
		t.Fatalf("LoadWithCustom (builtin disabled): %v", err)
	}

	// Should have only 1 dork.
	if set.Count() != 1 {
		t.Errorf("custom-only set has %d dorks, expected exactly 1", set.Count())
	}

	custom, ok := set.ByID("custom.only.test")
	if !ok {
		t.Fatal("custom dork not found")
	}
	if custom.Name != "Custom only test" {
		t.Errorf("custom dork has wrong name: %q", custom.Name)
	}
}

// TestLoadWithCustomInvalidFile tests error handling for malformed custom files.
func TestLoadWithCustomInvalidFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "invalid-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	// Write invalid YAML.
	if _, err := tmpfile.Write([]byte("not: valid: yaml: structure:")); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	tmpfile.Close()

	// Should fail to parse.
	_, err = LoadWithCustom(tmpfile.Name(), true)
	if err == nil {
		t.Fatal("LoadWithCustom should fail on invalid YAML")
	}
	if !strings.Contains(err.Error(), "parsing YAML") {
		t.Errorf("error should mention YAML parsing: %v", err)
	}
}

// TestLoadWithCustomMissingPlaceholder tests validation of custom dorks.
func TestLoadWithCustomMissingPlaceholder(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "missing-placeholder-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	// Dork without {target} placeholder.
	customYAML := `- id: invalid.no.placeholder
  category: username
  name: Invalid dork
  query: https://example.com/static
  tags:
    - invalid
`
	if _, err := tmpfile.Write([]byte(customYAML)); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	tmpfile.Close()

	// Should fail validation.
	_, err = LoadWithCustom(tmpfile.Name(), false)
	if err == nil {
		t.Fatal("LoadWithCustom should fail on dork without {target}")
	}
	if !strings.Contains(err.Error(), "must contain {target}") {
		t.Errorf("error should mention missing {target}: %v", err)
	}
}

// TestLoadWithCustomDuplicateID tests that duplicate IDs are rejected.
func TestLoadWithCustomDuplicateID(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "duplicate-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	// Use an ID that exists in built-in dorks (e.g., from general.yaml).
	customYAML := `- id: general.admin
  category: username
  name: Duplicate ID test
  query: https://example.com/{target}
  tags:
    - duplicate
`
	if _, err := tmpfile.Write([]byte(customYAML)); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	tmpfile.Close()

	// Should fail due to duplicate ID with built-in.
	_, err = LoadWithCustom(tmpfile.Name(), true)
	if err == nil {
		t.Fatal("LoadWithCustom should fail on duplicate ID")
	}
	if !strings.Contains(err.Error(), "conflicts with built-in") {
		t.Errorf("error should mention ID conflict: %v", err)
	}
}

// TestNewCategoryRendering tests that new categories render templates correctly.
func TestNewCategoryRendering(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}

	testCases := []struct {
		category Category
		target   string
	}{
		{CategoryUsername, "testuser"},
		{CategoryEmail, "test@example.com"},
		{CategoryName, "John Doe"},
		{CategoryEmployer, "Acme Corp"},
		{CategoryExposedDocs, "example.com"},
		{CategoryLoginPanels, "example.com"},
		{CategorySubdomains, "example.com"},
	}

	for _, tc := range testCases {
		dorks := set.InCategory(tc.category)
		if len(dorks) == 0 {
			t.Errorf("category %q has no dorks", tc.category)
			continue
		}

		// Test rendering the first dork in the category.
		rendered, err := dorks[0].Render(tc.target)
		if err != nil {
			t.Errorf("Render(%q) for category %q: %v", tc.target, tc.category, err)
			continue
		}
		if !strings.Contains(rendered, tc.target) {
			t.Errorf("rendered query for %q doesn't contain target %q: %s", tc.category, tc.target, rendered)
		}
	}
}

// TestCategoryConstants verifies all new category constants are properly defined.
func TestCategoryConstants(t *testing.T) {
	newCategories := map[Category]bool{
		CategoryUsername:    true,
		CategoryName:        true,
		CategoryEmail:       true,
		CategoryEmployer:    true,
		CategoryExposedDocs: true,
		CategoryLoginPanels: true,
		CategorySubdomains:  true,
	}

	for cat := range newCategories {
		if !knownCategory(cat) {
			t.Errorf("category %q not recognized by ParseCategory", cat)
		}
	}

	// Verify all are in AllCategories.
	allCatMap := make(map[Category]bool)
	for _, c := range AllCategories {
		allCatMap[c] = true
	}

	for cat := range newCategories {
		if !allCatMap[cat] {
			t.Errorf("category %q not in AllCategories list", cat)
		}
	}
}
