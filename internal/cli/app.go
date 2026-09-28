// Package cli implements the nzinga command-line interface. The same binary
// is also the interactive console. The package wires configuration, logging,
// output formatting, target authorization and the intelligence pipeline
// together and exposes the collect/correlate/report and management commands.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/viper"

	errs "github.com/QYVORA/qyvora-nzinga/internal/errors"
	"github.com/QYVORA/qyvora-nzinga/internal/events"
	"github.com/QYVORA/qyvora-nzinga/internal/intelligence/sources"
	"github.com/QYVORA/qyvora-nzinga/internal/logger"
	"github.com/QYVORA/qyvora-nzinga/internal/output"
	"github.com/QYVORA/qyvora-nzinga/internal/search"
	"github.com/QYVORA/qyvora-nzinga/internal/session"
	"github.com/QYVORA/qyvora-nzinga/internal/target"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// app is the shared state wired once per process and used by every command.
type appState struct {
	cfg     *viper.Viper
	log     *logger.Logger
	printer *output.Printer
	targets *target.Manager
	store   *session.Store
	reg     *sources.Registry
	dorks   *search.DorkSet

	eventStream *events.Stream
	eventSink   io.Writer

	// stdoutOwned is set when --events stdout is active: stdout then carries
	// only the JSONL event stream, so report rendering routes to stderr.
	stdoutOwned bool

	cfgFile   string
	verbose   bool
	quiet     bool
	jsonOut   bool
	outputFmt string
	eventsF   string
	dryRun    bool

	// initErr surfaces fatal config/flag errors from cobra's OnInitialize.
	initErr error
}

func newAppState() *appState { return &appState{} }

// requireTarget returns the current authorized target.
func (a *appState) requireTarget() (*models.Target, error) {
	t := a.targets.Current()
	if t == nil {
		return nil, errs.NewExitError(2, "no target selected; run 'nzinga target set' first")
	}
	if !t.Authorized() {
		return nil, errs.NewExitError(2, "current target is not authorized: "+t.DisplayName())
	}
	return t, nil
}

// persistSession saves a session to the store and records the path.
func (a *appState) persistSession(sess *models.Session) (string, error) {
	path, err := a.store.Save(sess)
	if err != nil {
		return "", err
	}
	sess.OutputDir = a.store.Dir()
	return path, nil
}

// emitf writes an informational line. In terminal mode it goes to the output
// writer; in machine-readable formats it goes to stderr so stdout stays pure.
func (a *appState) emitf(format string, args ...any) {
	if a.printer.Format() == output.FormatTerminal {
		_, _ = fmt.Fprintf(a.printer.Writer(), format+"\n", args...)
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// resolveEvents configures the event stream sink.
func (a *appState) resolveEvents(ctx context.Context) error {
	var w io.Writer
	if eventsDisabled(a.eventsF) {
		return nil
	}
	switch strings.ToLower(a.eventsF) {
	case "stdout":
		w = os.Stdout
		a.stdoutOwned = true
		// stdout carries only the JSONL event stream; every human and report
		// line routes to stderr (writer is set in initPrinter and may be
		// reassigned here because resolveEvents runs after initPrinter).
		a.printer.SetWriter(os.Stderr)
	case "stderr":
		w = os.Stderr
		// The event JSONL stream owns stderr in machine mode: route human
		// diagnostics away so strict JSONL consumers never see plain log
		// lines interleaved with events.
		a.log.SetWriter(io.Discard)
	default:
		// Truncated, not appended, so one file holds exactly one run's
		// events. Appending left no run boundary in the file, which matters
		// to anything tailing it.
		f, err := os.OpenFile(a.eventsF, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("opening events file: %w", err)
		}
		w = f
	}
	a.eventStream = events.NewStream(w)
	a.eventSink = w
	return nil
}

// eventsDisabled reports whether a --events value asks for no stream at all.
//
// The interactive guard and the event plumbing both need this answer, so the
// words are named once. A value that turns the stream off must not read as a
// request to send it somewhere: `tool --events off` opens the session
// happily, because there is nothing for it to contradict.
func eventsDisabled(spec string) bool {
	switch strings.ToLower(spec) {
	case "", "off", "none", "disable", "disabled":
		return true
	}
	return false
}
