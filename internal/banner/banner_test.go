package banner

import (
	"regexp"
	"strings"
	"testing"
)

// ansi matches the SGR escape sequences the renderers may add.
var ansi = regexp.MustCompile("\\x1b\\[[0-9;]*m")

// TestArtNonEmpty guards against the banner being accidentally emptied.
func TestArtNonEmpty(t *testing.T) {
	if strings.TrimSpace(Art) == "" {
		t.Fatal("Art is empty")
	}
}

// TestArtIsPlain guards the contract that Art carries no escape codes. Art is
// written to files and machine-readable streams, so colour has to live in
// Colorize and Render instead of leaking into the constant.
func TestArtIsPlain(t *testing.T) {
	if ansi.MatchString(Art) {
		t.Fatal("Art contains ANSI escape sequences; keep colour in Colorize")
	}
}

// TestArtWidths assures every banner line fits a standard terminal so the
// banner never breaks the console chrome.
func TestArtWidths(t *testing.T) {
	for i, line := range strings.Split(strings.TrimRight(Art, "\n"), "\n") {
		if len(line) > 110 {
			t.Fatalf("line %d too wide (%d cols): %q", i, len(line), line)
		}
	}
}

// TestArtTrailingNewline keeps the byte-for-byte contract with the banner
// file: content is raw, terminated by a single newline.
func TestArtTrailingNewline(t *testing.T) {
	if !strings.HasSuffix(Art, "\n") {
		t.Fatal("Art must end with a single trailing newline")
	}
}

// TestRenderPreservesArt checks that colouring is purely additive: stripping
// the escapes from Render must give back Art exactly, whatever the terminal
// profile happens to be. This is what keeps a redirected run byte-identical to
// the plain banner.
func TestRenderPreservesArt(t *testing.T) {
	if got := ansi.ReplaceAllString(Render(), ""); got != Art {
		t.Error("Render did not reduce to Art once escapes were removed")
	}
}

// TestColorizePreservesInput is the same additive guarantee for the single-row
// entry point the console draws with.
func TestColorizePreservesInput(t *testing.T) {
	const in = "  _  "
	if got := ansi.ReplaceAllString(Colorize(in), ""); got != in {
		t.Errorf("Colorize(%q) reduced to %q", in, got)
	}
}

// TestColorizeEmpty guards the empty case: an empty row must stay empty rather
// than come back wrapped in a reset sequence.
func TestColorizeEmpty(t *testing.T) {
	if got := Colorize(""); got != "" {
		t.Errorf("Colorize(\"\") = %q, want empty", got)
	}
}

// TestWidthMatchesArt pins Width to the art it describes. A stale width is
// worse than none: it is the number a caller uses to decide the banner fits.
func TestWidthMatchesArt(t *testing.T) {
	want := 0
	for _, line := range strings.Split(strings.TrimRight(Art, "\n"), "\n") {
		if n := len(line); n > want {
			want = n
		}
	}
	if Width != want {
		t.Errorf("Width = %d, want %d (widest row of Art)", Width, want)
	}
}

// TestGreenIsBrandAccent pins the brand colour so a well-meaning edit cannot
// quietly repaint every tool.
func TestGreenIsBrandAccent(t *testing.T) {
	if Green != "#06B66F" {
		t.Errorf("Green = %q, want %q", Green, "#06B66F")
	}
}
