package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	sess := models.NewSession()
	sess.ID = "sess-roundtrip"
	sess.Target = "domain:example.com"
	sess.RiskScore = 42
	sess.RiskLevel = "medium"
	path, err := store.Save(sess)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("session file must be owner-only, got %v", fi.Mode().Perm())
	}
	loaded, err := store.Load("sess-roundtrip")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Target != "domain:example.com" || loaded.RiskScore != 42 {
		t.Fatalf("roundtrip mismatch: %+v", loaded)
	}
}

func TestLoadMissingSession(t *testing.T) {
	store := NewStore(t.TempDir())
	if _, err := store.Load("sess-absent"); err == nil {
		t.Fatal("expected an error loading a missing session")
	}
}

func TestSaveNilSession(t *testing.T) {
	store := NewStore(t.TempDir())
	if _, err := store.Save(nil); err == nil {
		t.Fatal("expected an error saving nil")
	}
}

func TestListNewestFirstByMtime(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	now := time.Now().UTC()
	for i, id := range []string{"sess-old", "sess-mid", "sess-new"} {
		sess := models.NewSession()
		sess.ID = id
		if _, err := store.Save(sess); err != nil {
			t.Fatal(err)
		}
		stamp := now.Add(time.Duration(i) * time.Second)
		os.Chtimes(filepath.Join(dir, id+".session.json"), stamp, stamp)
	}
	ids, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 {
		t.Fatalf("expected 3 sessions, got %d", len(ids))
	}
	if ids[0] != "sess-new" || ids[1] != "sess-mid" || ids[2] != "sess-old" {
		t.Fatalf("expected newest-first ordering, got %v", ids)
	}
}

func TestLoadAcceptsFilePath(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	sess := models.NewSession()
	sess.ID = "sess-path"
	path, _ := store.Save(sess)
	loaded, err := store.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != "sess-path" {
		t.Fatalf("expected sess-path, got %q", loaded.ID)
	}
}
