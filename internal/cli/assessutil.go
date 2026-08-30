package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// errNoSession is returned by commands that require a saved session.
var errNoSession = errors.New("no saved sessions; run an assessment (e.g. 'nzinga assess --sim') first")

// establishTarget resolves the target for a collection run: the offline
// simulator always yields an authorized demo target; an explicit --target
// value is preferred; otherwise the current selected target is used.
func (a *appState) establishTarget(cmd *cobra.Command, opts targetOptions) (*models.Target, error) {
	if opts.sim {
		value := strings.TrimSpace(opts.value)
		if value == "" {
			value = "example.com"
		}
		t := &models.Target{
			Type:      opts.targetType(),
			Value:     value,
			Profile:   "standard",
			CreatedAt: time.Now().UTC(),
		}
		t.Auth = a.demoGrant(t)
		return t, nil
	}
	if strings.TrimSpace(opts.value) != "" {
		t := &models.Target{
			Type:      opts.targetType(),
			Value:     strings.TrimSpace(opts.value),
			CreatedAt: time.Now().UTC(),
		}
		return a.authorize(cmd, t)
	}
	t, err := a.requireTarget()
	if err != nil {
		return nil, err
	}
	return a.authorize(cmd, t)
}

func (a *appState) demoGrant(t *models.Target) models.Authorization {
	return models.Authorization{
		Granted:   true,
		GrantedAt: time.Now().UTC(),
		Scope:     "offline simulation dataset only; no network I/O",
		Method:    "demo",
		GrantedBy: userName(),
	}
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
