package search

import (
	"context"
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
