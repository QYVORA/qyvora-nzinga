package capabilities

import (
	"testing"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// TestCatalogSchemas locks the machine-readable tool contract: every tool
// advertises an input/output schema, and source tools carry the observation
// provenance record.
func TestCatalogSchemas(t *testing.T) {
	src := models.Source{
		ID:           "crt.sh",
		Name:         "crt.sh Certificate Transparency",
		Category:     models.CategoryCertificate,
		Capabilities: []models.Capability{models.CapCertEnumerate},
		Targets:      []models.TargetType{models.TargetDomain},
		Risk:         models.RiskS1,
		AuthRequired: true,
	}
	tools := Catalog([]models.Source{src}, nil)
	if len(tools) == 0 {
		t.Fatal("no tools in catalog")
	}
	for _, tool := range tools {
		if len(tool.Schema.Input) == 0 {
			t.Errorf("tool %s has no input schema", tool.ID)
		}
		if len(tool.Schema.Output) == 0 {
			t.Errorf("tool %s has no output schema", tool.ID)
		}
	}

	sourceTool := tools[0]
	if sourceTool.ID != "nzinga.analyze.correlate" && sourceTool.ID != "nzinga.crt.sh.certificate.enumerate" {
		t.Fatalf("unexpected first tool id %q", sourceTool.ID)
	}
	sourceTool, ok := findTool(tools, "nzinga.crt.sh.certificate.enumerate")
	if !ok {
		t.Fatal("source tool missing from catalog")
	}
	if sourceTool.Schema.Input[0].Name != "target" || !sourceTool.Schema.Input[0].Required {
		t.Errorf("source tool must require a target input, got %+v", sourceTool.Schema.Input[0])
	}
	seen := map[string]bool{}
	for _, f := range sourceTool.Schema.Output {
		seen[f.Name] = true
	}
	for _, want := range []string{"source", "source_type", "observed_at", "collected_at", "raw_reference", "hash"} {
		if !seen[want] {
			t.Errorf("source tool output schema missing field %q", want)
		}
	}
}

// TestAnalysisSchema verifies the framework tools declare session inputs.
func TestAnalysisSchema(t *testing.T) {
	tools := Catalog(nil, nil)
	for _, tool := range tools {
		if tool.ID != "nzinga.analyze.correlate" {
			continue
		}
		if tool.Schema.Input[0].Name != "session" {
			t.Errorf("analysis tool input name = %q, want session", tool.Schema.Input[0].Name)
		}
		if tool.Schema.Output[0].Name != "findings" {
			t.Errorf("analysis tool first output = %q, want findings", tool.Schema.Output[0].Name)
		}
		return
	}
	t.Fatal("analysis tool missing from catalog")
}

func findTool(tools []Tool, id string) (Tool, bool) {
	for _, tool := range tools {
		if tool.ID == id {
			return tool, true
		}
	}
	return Tool{}, false
}
