package target

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

func authorizedTarget(name, value string) *models.Target {
	return &models.Target{
		Type:  models.TargetDomain,
		Value: value,
		Auth:  models.Authorization{Granted: true, Method: "test"},
	}
}

func TestSetPersistsAcrossManagers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	tgt := authorizedTarget("test", "example.com")
	m1 := NewManager(path)
	if err := m1.Set(tgt); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("target state must be owner-only, got %v", fi.Mode().Perm())
	}
	m2 := NewManager(path)
	cur := m2.Current()
	if cur == nil || cur.Value != "example.com" {
		t.Fatalf("current target not restored, got %+v", cur)
	}
}

func TestSetRefusesUnauthorizedTarget(t *testing.T) {
	m := NewManager(filepath.Join(t.TempDir(), "targets.json"))
	err := m.Set(&models.Target{Type: models.TargetDomain, Value: "example.com"})
	if err == nil {
		t.Fatal("unauthorized target must be refused")
	}
	if m.Current() != nil {
		t.Fatal("refused target must not become current")
	}
}

func TestNewManagerResolvesParentDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	path := filepath.Join(dir, "targets.json")
	m := NewManager(path)
	if err := m.Set(authorizedTarget("test", "example.org")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected state file to be created: %v", err)
	}
}

func TestCorruptStateFallsBackToEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(path)
	if m.Current() != nil {
		t.Fatal("corrupt state must degrade to an empty manager")
	}
}

func TestListAndGet(t *testing.T) {
	m := NewManager("")
	tgt := authorizedTarget("test", "example.com")
	if err := m.Set(tgt); err != nil {
		t.Fatal(err)
	}
	if got, ok := m.Get(tgt.ID); !ok || got.Value != "example.com" {
		t.Fatalf("Get failed: %+v", got)
	}
	got := m.List()
	if len(got) != 1 {
		t.Fatalf("expected 1 target, got %d", len(got))
	}
}
