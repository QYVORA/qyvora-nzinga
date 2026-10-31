package cli

import (
	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-nzinga/internal/capabilities"
	"github.com/QYVORA/qyvora-nzinga/internal/version"
)

// capabilityDocument is the machine contract shape shared by QYVORA
// frameworks.
type capabilityDocument struct {
	Framework     string              `json:"framework"`
	Version       string              `json:"version"`
	OutputFormats []string            `json:"output_formats"`
	Capabilities  []capabilities.Tool `json:"capabilities"`
	Commands      []capabilities.Tool `json:"commands"`
}

func newCapabilitiesCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "capabilities",
		Aliases: []string{"caps"},
		Short:   "List nzinga's machine-readable tool contract",
		Args:    cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			printCapabilitiesTable()
		},
	}
}

func printCapabilitiesTable() {
	list := capabilities.New(app.reg.List())
	switch app.printerFormat() {
	case outputFormatJSON, outputFormatYAML, outputFormatHTML, outputFormatMD:
		app.printer.Print(capabilityDocument{
			Framework:     version.Framework,
			Version:       version.GetInfo().Version,
			OutputFormats: []string{"terminal", "json", "yaml", "markdown", "html"},
			Capabilities:  list,
			Commands:      list,
		})
	default:
		app.printer.PrintTable(
			[]string{"id", "name", "category", "risk", "auth"},
			capRows(list),
		)
	}
}

func capRows(tools []capabilities.Tool) [][]string {
	rows := make([][]string, 0, len(tools))
	for _, t := range tools {
		rows = append(rows, []string{
			t.ID, t.Name, t.Category,
			string(t.Risk), yes(t.AuthRequired),
		})
	}
	return rows
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
