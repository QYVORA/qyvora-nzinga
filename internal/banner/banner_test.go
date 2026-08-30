package banner

import (
	"strings"
	"testing"
)

// TestArtNonEmpty guards against the banner being accidentally emptied.
func TestArtNonEmpty(t *testing.T) {
	if strings.TrimSpace(Art) == "" {
		t.Fatal("Art is empty")
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
	if strings.Contains(Art, "`") || strings.Contains(Art, "\\") {
		t.Fatal("Art must not contain raw-literal-breaking characters")
	}
}
