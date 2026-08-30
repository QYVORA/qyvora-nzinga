// Package session manages intelligence sessions: creation, persistence to
// disk, and loading. A session tracks the target, discovered entities,
// relationships, findings, evidence, observations, claims and analysis state
// so an operator can understand exactly what happened during a run.
package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// DefaultDir is where sessions are stored when no directory is configured.
var DefaultDir = filepath.Join(".", "sessions")

// Store persists sessions to disk as JSON.
type Store struct {
	dir string
}

// NewStore returns a session store rooted at dir (or the default).
func NewStore(dir string) *Store {
	if dir == "" {
		dir = DefaultDir
	}
	return &Store{dir: dir}
}

// Dir returns the resolved store directory.
func (s *Store) Dir() string { return s.dir }

// Save writes a session to disk and returns the file path.
func (s *Store) Save(sess *models.Session) (string, error) {
	if sess == nil {
		return "", fmt.Errorf("session is nil")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return "", fmt.Errorf("creating session dir: %w", err)
	}
	path := filepath.Join(s.dir, sess.ID+".session.json")
	data, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// Load reads a session from a file path or session ID.
func (s *Store) Load(id string) (*models.Session, error) {
	path := id
	if !strings.HasSuffix(path, ".session.json") {
		path = filepath.Join(s.dir, id+".session.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sess models.Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

// List returns the session IDs, newest first by file modification time.
func (s *Store) List() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	type item struct {
		id string
		at time.Time
	}
	var items []item
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".session.json") {
			continue
		}
		at := time.Time{}
		if info, err := e.Info(); err == nil {
			at = info.ModTime()
		}
		items = append(items, item{id: strings.TrimSuffix(name, ".session.json"), at: at})
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].at.Equal(items[j].at) {
			return items[i].at.After(items[j].at)
		}
		return items[i].id < items[j].id
	})
	ids := make([]string, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.id)
	}
	return ids, nil
}

// Begin returns a fresh session bound to the given target, or a fresh session
// when the target is nil.
func Begin(target *models.Target) *models.Session {
	s := models.NewSession()
	if target != nil {
		s.TargetID = target.ID
		s.Profile = target.Profile
	}
	return s
}

// Finished marks the session end and returns it (for chaining).
func Finished(sess *models.Session) *models.Session {
	if sess != nil {
		sess.End = time.Now().UTC()
	}
	return sess
}
