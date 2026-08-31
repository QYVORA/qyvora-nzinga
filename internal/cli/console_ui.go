package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/QYVORA/qyvora-nzinga/internal/banner"
)

// amber is the brand accent (QYVORA Brand Amber 255,176,0).
const (
	ansiAmber = "\x1b[38;2;255;176;0m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
	ansiRed   = "\x1b[91m"
	ansiWhite = "\x1b[37m"
	ansiReset = "\x1b[0m"
)

// kvLabelWidth is the fixed visible width used for "key: value" labels so the
// values of consecutive KV lines always line up in a column.
const kvLabelWidth = 22

// consoleUI renders the console chrome: prompt, banner, HUD, tables. Color is
// enabled only when the writer is a terminal and NO_COLOR is not set, so
// piped/scripted output stays plain.
type consoleUI struct {
	out   io.Writer
	color bool
}

func newConsoleUI(w io.Writer) *consoleUI {
	u := &consoleUI{out: w}
	if os.Getenv("NO_COLOR") == "" {
		u.color = writerIsTerminal(w)
	}
	return u
}

// paint wraps s in code/Reset when colors are active; empty strings stay
// untouched so padding math never sees invisible ANSI bytes.
func (u *consoleUI) paint(s, code string) string {
	if !u.color || s == "" {
		return s
	}
	return code + s + ansiReset
}

// Amber paints a string in the brand amber accent.
func (u *consoleUI) Amber(s string) string { return u.paint(s, ansiAmber) }

// Prompt returns the interactive line prompt.
func (u *consoleUI) Prompt(name string) string {
	return u.paint(name, ansiBold+ansiAmber) + u.paint(" > ", ansiBold+ansiWhite)
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
	line := fmt.Sprintf("target: %s · profile: %s · cwd: %s · %s", target, profile, cwd, version)
	_, _ = fmt.Fprintln(u.out, u.Amber(line))
	_, _ = fmt.Fprintln(u.out)
}

// Status prints a status line with a symbol.
func (u *consoleUI) Status(symbol, format string, args ...any) {
	_, _ = fmt.Fprintf(u.out, "  %s %s\n", u.Glyph(symbol), u.White(fmt.Sprintf(format, args...)))
}

// Glyph returns a bracketed status glyph, colored per convention.
func (u *consoleUI) Glyph(glyph string) string {
	switch glyph {
	case "+":
		return u.paint("[+]", ansiAmber)
	case "*":
		return u.paint("[*]", ansiWhite)
	case "!", "warn":
		return u.paint("[!]", ansiAmber)
	case "x", "X", "err":
		return u.paint("[x]", ansiBold+ansiRed)
	case ">":
		return u.paint("[>]", ansiBold+ansiAmber)
	case "-":
		return u.paint("[-]", ansiDim+ansiWhite)
	default:
		return u.paint("["+glyph+"]", ansiBold+ansiAmber)
	}
}

// White paints a string plain white (information).
func (u *consoleUI) White(s string) string { return u.paint(s, ansiWhite) }

// KV prints a key/value line with the value aligned in a column so the values
// of consecutive KV lines line up.
func (u *consoleUI) KV(key string, value string) {
	_, _ = fmt.Fprintf(u.out, "  %s %s\n", padTo(u.paint(key+":", ansiBold+ansiWhite), kvLabelWidth), u.White(value))
}

// Err prints an error line.
func (u *consoleUI) Err(format string, args ...any) {
	_, _ = fmt.Fprintf(u.out, "  %s %s\n", u.paint("[x]", ansiBold+ansiRed), u.paint(fmt.Sprintf(format, args...), ansiRed))
}

// Section prints a clean section header.
func (u *consoleUI) Section(name string) {
	_, _ = fmt.Fprintf(u.out, "\n  %s\n", u.Amber(strings.ToUpper(name)))
}

// Table prints an aligned table. Column widths are driven by the widest
// visible cell (ANSI codes and wide characters accounted for), so headers and
// rows stay aligned in both color and plain modes. Missing trailing cells are
// padded so a ragged row never skews the following columns.
func (u *consoleUI) Table(header []string, rows [][]string) {
	if len(header) == 0 {
		return
	}
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = runeWidth(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && runeWidth(cell) > widths[i] {
				widths[i] = runeWidth(cell)
			}
		}
	}

	var b strings.Builder
	for i, h := range header {
		if i > 0 {
			b.WriteString("  ")
		}
		b.WriteString(padTo(u.paint(strings.ToUpper(h), ansiBold+ansiAmber), widths[i]))
	}
	_, _ = fmt.Fprintln(u.out, strings.TrimRight(b.String(), " "))

	for _, row := range rows {
		var rb strings.Builder
		for i := 0; i < len(widths); i++ {
			if i > 0 {
				rb.WriteString("  ")
			}
			var cell string
			if i < len(row) {
				cell = row[i]
			}
			rb.WriteString(padTo(u.White(cell), widths[i]))
		}
		_, _ = fmt.Fprintln(u.out, strings.TrimRight(rb.String(), " "))
	}
}

// Rule prints a soft section break — a blank line, never a rule line.
func (u *consoleUI) Rule() {
	_, _ = fmt.Fprintln(u.out)
}

// outline prints a banner line with the amber accent, honoring NO_COLOR.
func (u *consoleUI) outline(line string) {
	_, _ = fmt.Fprintln(u.out, u.Amber(line))
}

// runeWidth counts the display width of s, stripping ANSI codes first and
// counting wide (CJK/emoji) characters as two columns.
func runeWidth(s string) int {
	if strings.Contains(s, "\x1b") {
		s = stripANSI(s)
	}
	n := 0
	for _, r := range s {
		if isWideRune(r) {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// isWideRune reports whether r occupies two terminal columns. The ranges
// mirror the Unicode EastAsianWidth property used by wcwidth.
func isWideRune(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F,
		r >= 0x2329 && r <= 0x232A,
		r >= 0x2E80 && r <= 0xA4CF,
		r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF,
		r >= 0xFE10 && r <= 0xFE19,
		r >= 0xFE30 && r <= 0xFE6F,
		r >= 0xFF00 && r <= 0xFF60,
		r >= 0xFFE0 && r <= 0xFFE6,
		r >= 0x1F300 && r <= 0x1F64F,
		r >= 0x1F900 && r <= 0x1F9FF:
		return true
	}
	return false
}

// stripANSI removes ANSI escape sequences from s.
func stripANSI(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\x1b' {
			j := i + 1
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

// padTo pads s (which may contain ANSI codes) with trailing spaces to a
// visible width of n columns.
func padTo(s string, n int) string {
	pad := n - runeWidth(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

// writerIsTerminal reports whether w is an interactive character device.
func writerIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
