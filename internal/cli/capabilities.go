package cli

import (
	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-nzinga/internal/capabilities"
)

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
	case outputFormatJSON, outputFormatYAML:
		app.printer.Print(list)
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
