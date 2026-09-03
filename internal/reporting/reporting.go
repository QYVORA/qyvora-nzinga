// Package reporting renders a completed session into human- and
// machine-readable reports. It is transport- and policy-free: given a session
// it produces deterministic terminal, markdown, HTML, JSON and YAML output.
package reporting

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/QYVORA/qyvora-nzinga/internal/version"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// Format enumerates supported report renderers.
type Format string

const (
	FormatTerminal Format = "terminal"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
	FormatJSON     Format = "json"
	FormatYAML     Format = "yaml"
)

// ParseFormat maps a string to a Format.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(s)) {
	case FormatTerminal, FormatMarkdown, FormatHTML, FormatJSON, FormatYAML:
		return Format(strings.ToLower(s)), nil
	default:
		return "", fmt.Errorf("unsupported report format %q", s)
	}
}

// Render produces the report for a session in the given format.
func Render(s *models.Session, format Format) (string, error) {
	switch format {
	case FormatJSON:
		return renderJSON(s)
	case FormatYAML:
		return renderYAML(s)
	case FormatMarkdown:
		return renderMarkdown(s), nil
	case FormatHTML:
		return renderHTML(s), nil
	default:
		return renderTerminal(s), nil
	}
}

func renderJSON(s *models.Session) (string, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// renderYAML reflects the JSON representation so YAML and JSON share the same
// snake_case keys instead of each renderer using its own field mapping.
func renderYAML(s *models.Session) (string, error) {
	jsonData, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	var value any
	if err := json.Unmarshal(jsonData, &value); err != nil {
		return "", err
	}
	data, err := yaml.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func renderTerminal(s *models.Session) string {
	var b strings.Builder
	writef(&b, "nzinga intelligence report")
	writef(&b, "  session:  %s", s.ID)
	writef(&b, "  target:   %s", orDash(s.Target))
	writef(&b, "  profile:  %s", orDash(s.Profile))
	writef(&b, "  started:  %s", s.Start.Format(time.RFC3339))
	if !s.End.IsZero() {
		writef(&b, "  finished: %s", s.End.Format(time.RFC3339))
	}
	writef(&b, "  risk:     %s (%s)", orDash(s.RiskLevel), scoreDisplay(s.RiskScore))

	writef(&b, "")
	writef(&b, "discovered entities")
	writef(&b, "  domains        %d", len(s.Domains))
	writef(&b, "  hostnames      %d", len(s.Hostnames))
	writef(&b, "  ip addresses   %d", len(s.IPs))
	writef(&b, "  organizations  %d", len(s.Organizations))
	writef(&b, "  people         %d", len(s.People))
	writef(&b, "  emails         %d", len(s.Emails))
	writef(&b, "  usernames      %d", len(s.Usernames))
	writef(&b, "  repositories   %d", len(s.Repositories))
	writef(&b, "  certificates   %d", len(s.Certificates))
	writef(&b, "  asns           %d", len(s.ASNs))

	writef(&b, "")
	writef(&b, "intelligence")
	writef(&b, "  observations %d, claims %d", len(s.Observations), len(s.Claims))
	writef(&b, "  graph nodes %d, edges %d", len(s.Nodes), len(s.Edges))

	if len(s.Claims) > 0 {
		writef(&b, "")
		writef(&b, "claims (%d)", len(s.Claims))
		for _, c := range s.Claims {
			writef(&b, "  [%s] %s", c.Type, c.Assertion)
			writef(&b, "      subject=%s confidence=%s observations=%d", orDash(c.Subject), c.Confidence, len(c.ObservationIDs))
		}
	}

	if len(s.Findings) > 0 {
		writef(&b, "")
		writef(&b, "findings (%d)", len(s.Findings))
		for _, f := range s.Findings {
			writef(&b, "  [%s] %s (%s)", f.Severity, f.Title, f.RuleID)
			writef(&b, "      confidence=%s status=%s", f.Confidence, f.Status)
		}
	}
	if len(s.Evidence) > 0 {
		writef(&b, "")
		writef(&b, "evidence (%d items)", len(s.Evidence))
		for _, ev := range s.Evidence {
			writef(&b, "  %s %s <- %s [%s]", ev.ID, orDash(ev.Data), orDash(ev.Target), ev.Source)
		}
	}
	if len(s.Errors) > 0 {
		writef(&b, "")
		writef(&b, "errors (%d)", len(s.Errors))
		for _, e := range s.Errors {
			writef(&b, "  - %s", e)
		}
	}
	return b.String()
}

func renderMarkdown(s *models.Session) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s intelligence report\n\n", version.Framework)
	fmt.Fprintf(&b, "| field | value |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| session | `%s` |\n", s.ID)
	fmt.Fprintf(&b, "| target | `%s` |\n", orDash(s.Target))
	fmt.Fprintf(&b, "| profile | %s |\n", orDash(s.Profile))
	fmt.Fprintf(&b, "| started | %s |\n", s.Start.Format(time.RFC3339))
	fmt.Fprintf(&b, "| risk | **%s** (%s) |\n", orDash(s.RiskLevel), scoreDisplay(s.RiskScore))
	b.WriteString("\n## Discovered entities\n\n")
	fmt.Fprintf(&b, "- domains: %d\n", len(s.Domains))
	fmt.Fprintf(&b, "- hostnames: %d\n", len(s.Hostnames))
	fmt.Fprintf(&b, "- ip addresses: %d\n", len(s.IPs))
	fmt.Fprintf(&b, "- organizations: %d\n", len(s.Organizations))
	fmt.Fprintf(&b, "- people: %d\n", len(s.People))
	fmt.Fprintf(&b, "- emails: %d\n", len(s.Emails))
	fmt.Fprintf(&b, "- usernames: %d\n", len(s.Usernames))
	fmt.Fprintf(&b, "- repositories: %d\n", len(s.Repositories))
	fmt.Fprintf(&b, "- certificates: %d\n", len(s.Certificates))
	fmt.Fprintf(&b, "- asns: %d\n", len(s.ASNs))
	fmt.Fprintf(&b, "- observations: %d | claims: %d | graph: %d nodes, %d edges\n",
		len(s.Observations), len(s.Claims), len(s.Nodes), len(s.Edges))

	writeMarkdownList(&b, "Usernames", toStrings(s.Usernames))
	writeMarkdownList(&b, "Emails", toStrings(s.Emails))

	if len(s.Claims) > 0 {
		fmt.Fprintf(&b, "\n## Correlation claims (%d)\n\n", len(s.Claims))
		b.WriteString("| type | subject | assertion | confidence | observations |\n| --- | --- | --- | --- | --- |\n")
		for _, c := range s.Claims {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %d |\n", c.Type, orDash(c.Subject), c.Assertion, c.Confidence, len(c.ObservationIDs))
		}
	}

	if len(s.Findings) > 0 {
		fmt.Fprintf(&b, "\n## Findings (%d)\n\n", len(s.Findings))
		b.WriteString("| severity | rule | title | confidence | status |\n| --- | --- | --- | --- | --- |\n")
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s |\n", f.Severity, f.RuleID, f.Title, f.Confidence, f.Status)
		}
	}
	if len(s.Evidence) > 0 {
		fmt.Fprintf(&b, "\n## Evidence (%d)\n\n", len(s.Evidence))
		b.WriteString("| id | source | target | data |\n| --- | --- | --- | --- |\n")
		for _, ev := range s.Evidence {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", ev.ID, ev.Source, orDash(ev.Target), orDash(ev.Data))
		}
	}
	return b.String()
}

func renderHTML(s *models.Session) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>nzinga report</title>")
	b.WriteString("<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px 8px;text-align:left}</style>")
	b.WriteString("</head><body>\n")
	fmt.Fprintf(&b, "<h1>%s intelligence report</h1>\n", html.EscapeString(version.Framework))
	fmt.Fprintf(&b, "<p>session <code>%s</code> · target <code>%s</code> · risk <b>%s</b> (%s)</p>\n",
		html.EscapeString(s.ID), html.EscapeString(orDash(s.Target)), html.EscapeString(s.RiskLevel), scoreDisplay(s.RiskScore))
	b.WriteString("<h2>Discovered entities</h2>\n<table>\n")
	b.WriteString("<tr><th>domain</th><th>hostname</th><th>ip</th><th>org</th><th>person</th><th>email</th><th>username</th><th>repo</th><th>certificate</th><th>asn</th></tr>\n")
	fmt.Fprintf(&b, "<tr><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr>\n</table>\n",
		len(s.Domains), len(s.Hostnames), len(s.IPs), len(s.Organizations), len(s.People),
		len(s.Emails), len(s.Usernames), len(s.Repositories), len(s.Certificates), len(s.ASNs))
	if len(s.Findings) > 0 {
		fmt.Fprintf(&b, "<h2>Findings (%d)</h2>\n<table>\n<tr><th>severity</th><th>rule</th><th>title</th></tr>\n", len(s.Findings))
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "<tr><td>%s</td><td><code>%s</code></td><td>%s</td></tr>\n",
				html.EscapeString(string(f.Severity)), html.EscapeString(f.RuleID), html.EscapeString(f.Title))
		}
		b.WriteString("</table>\n")
	}
	b.WriteString("</body></html>\n")
	return b.String()
}

func writef(b *strings.Builder, format string, args ...any) {
	fmt.Fprintf(b, format+"\n", args...)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func scoreDisplay(score int) string {
	if score == 0 {
		return "-"
	}
	return fmt.Sprintf("%d/100", score)
}

func writeMarkdownList(b *strings.Builder, title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "\n## %s\n\n", title)
	for _, it := range items {
		fmt.Fprintf(b, "- %s\n", it)
	}
}

// toStrings flattens entity slices to their display names for compact
// reporting of identity-type entities.
func toStrings(v any) []string {
	switch es := v.(type) {
	case []*models.Username:
		out := make([]string, 0, len(es))
		for _, e := range es {
			if e != nil {
				out = append(out, e.Handle)
			}
		}
		return out
	case []*models.Email:
		out := make([]string, 0, len(es))
		for _, e := range es {
			if e != nil {
				out = append(out, e.Address)
			}
		}
		return out
	default:
		return nil
	}
}
