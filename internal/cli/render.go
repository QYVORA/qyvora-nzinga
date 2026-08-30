package cli

import (
	"context"

	"github.com/QYVORA/qyvora-nzinga/internal/reporting"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// renderSession prints the full report for a session in the active format.
func renderSession(ctx context.Context, sess *models.Session) error {
	format := app.printerFormat()
	f, err := reporting.ParseFormat(format)
	if err != nil {
		return err
	}
	content, err := reporting.Render(sess, f)
	if err != nil {
		return err
	}
	_, _ = app.printer.Writer().Write([]byte(content))
	_, _ = app.printer.Writer().Write([]byte("\n"))
	return nil
}

// renderFindings lists the findings of a session.
func renderFindings(sess *models.Session) error {
	rows := make([][]string, 0, len(sess.Findings))
	for _, f := range sess.Findings {
		if f == nil {
			continue
		}
		rows = append(rows, []string{
			f.RuleID, string(f.Severity), f.Title, string(f.Confidence), string(f.Status),
		})
	}
	switch app.printerFormat() {
	case outputFormatJSON, outputFormatYAML, outputFormatHTML, outputFormatMD:
		app.printer.Print(rows)
	default:
		if len(rows) == 0 {
			app.emitf("no findings in the latest session")
			return nil
		}
		app.printer.PrintTable([]string{"rule", "severity", "title", "confidence", "status"}, rows)
	}
	return nil
}

// renderEvidence lists the evidence of a session.
func renderEvidence(sess *models.Session) error {
	rows := make([][]string, 0, len(sess.Evidence))
	for _, ev := range sess.Evidence {
		if ev == nil {
			continue
		}
		rows = append(rows, []string{ev.ID, ev.Source, orDash(ev.Target), orDash(ev.Data)})
	}
	switch app.printerFormat() {
	case outputFormatJSON, outputFormatYAML, outputFormatHTML, outputFormatMD:
		app.printer.Print(rows)
	default:
		if len(rows) == 0 {
			app.emitf("no evidence in the latest session")
			return nil
		}
		app.printer.PrintTable([]string{"id", "source", "target", "data"}, rows)
	}
	return nil
}

// renderGraph lists nodes and edges of a session.
func renderGraph(sess *models.Session) error {
	if app.printerFormat() == outputFormatJSON || app.printerFormat() == outputFormatYAML {
		app.printer.Print(map[string]any{"nodes": sess.Nodes, "edges": sess.Edges})
		return nil
	}
	app.emitf("graph: %d nodes, %d edges", len(sess.Nodes), len(sess.Edges))
	nodeRows := make([][]string, 0, len(sess.Nodes))
	for _, n := range sess.Nodes {
		if n == nil {
			continue
		}
		nodeRows = append(nodeRows, []string{n.ID, string(n.Kind), orDash(n.Label)})
	}
	if len(nodeRows) > 0 {
		app.printer.PrintTable([]string{"id", "kind", "label"}, nodeRows)
	}
	edgeRows := make([][]string, 0, len(sess.Edges))
	for _, e := range sess.Edges {
		if e == nil {
			continue
		}
		edgeRows = append(edgeRows, []string{string(e.Type), e.From, e.To, orDash(e.Source)})
	}
	if len(edgeRows) > 0 {
		app.printer.PrintTable([]string{"type", "from", "to", "source"}, edgeRows)
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
