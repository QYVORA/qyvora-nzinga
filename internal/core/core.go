// Package core defines the shared environment every pipeline stage receives.
// It bundles the target, session, registry, configuration and event stream so
// stages need no global state.
package core

import (
	"github.com/spf13/viper"

	"github.com/QYVORA/qyvora-nzinga/internal/events"
	"github.com/QYVORA/qyvora-nzinga/internal/intelligence/sources"
	"github.com/QYVORA/qyvora-nzinga/internal/logger"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// Env is the shared context passed through the pipeline stages.
type Env struct {
	Target   *models.Target
	Session  *models.Session
	Registry *sources.Registry
	Config   *viper.Viper
	Log      *logger.Logger
	Events   *events.Stream
	Offline  bool
}
