package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/QYVORA/qyvora-nzinga/internal/banner"
)

// amber is the brand accent (QYVORA Brand Amber 255,176,0).
var amber = color.New(color.FgHiYellow)

// consoleUI renders the console chrome: prompt, banner, HUD, tables.
type consoleUI struct {
	out io.Writer
}

func newConsoleUI(w io.Writer) *consoleUI { return &consoleUI{out: w} }

// Prompt returns the interactive line prompt.
func (u *consoleUI) Prompt(name string) string {
	return amber.Sprint(name + "> ")
}

// Banner prints the brand ASCII banner centered.
func (u *consoleUI) Banner(title string) {
	for _, line := range strings.Split(strings.TrimRight(banner.Art, "\n"), "\n") {
		u.outline(line)
	}
	_, _ = fmt.Fprintln(u.out)
	u.Section(title)
}

// BannerFoot prints the version line under the banner.
func (u *consoleUI) BannerFoot(version string) {
	u.KV("framework", "nzinga")
	u.KV("version", version)
	u.KV("docs", "https://qyvora.dev/docs/nzinga")
}

// HUD renders the always-on status line.
func (u *consoleUI) HUD(target, profile, cwd, version string) {
	line := fmt.Sprintf("[target: %s] [profile: %s] [cwd: %s] [%s]", target, profile, cwd, version)
	_, _ = fmt.Fprintln(u.out, amber.Sprintf("─ %s", line))
	_, _ = fmt.Fprintln(u.out, strings.Repeat("─", 68))
}

// Status prints a status line with a symbol.
func (u *consoleUI) Status(symbol, format string, args ...any) {
	_, _ = fmt.Fprintf(u.out, " %s %s\n", amber.Sprint(symbol), fmt.Sprintf(format, args...))
}

// KV prints a key/value line.
func (u *consoleUI) KV(key string, value string) {
	_, _ = fmt.Fprintf(u.out, "  %-12s %s\n", amber.Sprint(key), value)
}

// Err prints an error line.
func (u *consoleUI) Err(format string, args ...any) {
	_, _ = fmt.Fprintf(u.out, " %s %s\n", color.RedString("!"), fmt.Sprintf(format, args...))
}

// Section prints a section header.
func (u *consoleUI) Section(name string) {
	_, _ = fmt.Fprintf(u.out, "== %s ==\n", amber.Sprint(name))
}

// Table prints a simple aligned table.
func (u *consoleUI) Table(header []string, rows [][]string) {
	colWidths := make([]int, len(header))
	for i, h := range header {
		colWidths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}
	hdr := ""
	for i, h := range header {
		hdr += fmt.Sprintf("%-*s  ", colWidths[i], amber.Sprint(h))
	}
	_, _ = fmt.Fprintln(u.out, hdr)
	_, _ = fmt.Fprintln(u.out, strings.Repeat("─", sumWidths(colWidths)+len(colWidths)*2))
	for _, row := range rows {
		line := ""
		for i, cell := range row {
			line += fmt.Sprintf("%-*s  ", colWidths[i], cell)
		}
		_, _ = fmt.Fprintln(u.out, strings.TrimRight(line, " "))
	}
}

// Rule prints a horizontal rule.
func (u *consoleUI) Rule() {
	_, _ = fmt.Fprintln(u.out, strings.Repeat("─", 68))
}

func sumWidths(widths []int) int {
	total := 0
	for _, w := range widths {
		total += w
	}
	return total
}

// outline prints a banner line with the amber accent, honoring NO_COLOR.
func (u *consoleUI) outline(line string) {
	_, _ = fmt.Fprintln(u.out, amber.Sprint(line))
}
