package cli

import (
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

func printSourcesTable() {
	list := app.reg.List()
	switch app.printerFormat() {
	case outputFormatJSON, outputFormatYAML:
		app.printer.Print(list)
	default:
		rows := make([][]string, 0, len(list))
		for _, s := range list {
			rows = append(rows, []string{
				s.ID, s.Name, string(s.Category), capsSummary(s.Capabilities),
				string(s.Risk), yes(s.AuthRequired), yes(s.Public),
			})
		}
		app.printer.PrintTable(
			[]string{"id", "name", "category", "capabilities", "risk", "auth", "public"},
			rows,
		)
	}
}

func printSourcesFull() {
	list := app.reg.List()
	switch app.printerFormat() {
	case outputFormatJSON, outputFormatYAML:
		app.printer.Print(list)
	default:
		for _, s := range list {
			app.emitf("%s", s.Name)
			app.emitf("  id:          %s", s.ID)
			app.emitf("  category:    %s", s.Category)
			app.emitf("  capabilities:%s", capsSummary(s.Capabilities))
			app.emitf("  targets:     %s", joinTargets(s.Targets))
			app.emitf("  risk:        %s  auth: %s  public: %s", s.Risk, yes(s.AuthRequired), yes(s.Public))
			if s.Description != "" {
				app.emitf("  description: %s", s.Description)
			}
			app.emitf("")
		}
	}
}

func capsSummary(caps []models.Capability) string {
	out := ""
	for i, c := range caps {
		if i > 0 {
			out += ", "
		}
		out += string(c)
	}
	if out == "" {
		return "-"
	}
	return out
}

func joinTargets(ts []models.TargetType) string {
	out := ""
	for i, t := range ts {
		if i > 0 {
			out += ", "
		}
		out += string(t)
	}
	if out == "" {
		return "-"
	}
	return out
}
