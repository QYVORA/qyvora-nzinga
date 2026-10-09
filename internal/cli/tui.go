package cli

import (
	"context"
	"fmt"
	"os"

	errs "github.com/QYVORA/qyvora-nzinga/internal/errors"
	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-nzinga/internal/capabilities"
	"github.com/QYVORA/qyvora-nzinga/internal/version"
	"github.com/QYVORA/qyvora-tui"
)

// runTUI starts the interactive terminal application.
//
// The TUI is a presentation layer over the same command tree the one-shot CLI
// exposes. Commands run in-process through ExecuteArgsContext and the interface
// reads the structured JSONL event stream, so it never parses human-readable
// output and a command behaves identically whether it was typed at a prompt or
// run in a script.
//
// The root command is passed in rather than referenced directly: the root's own
// default action calls this function, so naming the package-level root here
// would be an initialisation cycle.
func runTUI(root *cobra.Command, ctx context.Context) error {
	// A TUI needs a terminal. When stdout is redirected, or when the process is
	// driven by something that is not a person, fall through to ordinary
	// behaviour. Drawing a full-screen interface into a pipe would fill it with
	// escape codes and destroy the machine-readable output the tool exists to
	// produce.
	if !tui.IsInteractive(os.Stdout) {
		return root.Help()
	}

	// A machine event destination and the interface are contradictory: one
	// screen cannot hand the same bytes to a renderer and to a file. The
	// destination used to be ignored in silence, so a bare
	// `--events out.jsonl` opened the session and wrote no file.
	//
	// The flag has to have been *asked for*, not merely be set. This tool's
	// --events may default to a real destination so the stream is always on, and
	// testing the value alone would refuse every ordinary interactive run.
	if root.Flags().Changed("events") && !eventsDisabled(app.eventsF) {
		return errs.NewExitError(2, "cannot open the interactive session with a machine event destination (--events); the session transcript is already its event stream. Run a command for machine output, or drop --events to use the session.")
	}

	runner := &tui.InProcessRunner{
		ToolName: "nzinga",
		Execute:  ExecuteArgsContext,
		Meta:     tuiCommands(root),
	}

	// The capability registry is built from the same live source registry the
	// `capabilities` command reads, through the same normaliser, so the F1 view
	// and the `capabilities -o json` output cannot disagree.
	caps, err := tui.CapabilitiesFrom("nzinga", capabilities.New(app.reg.List()))
	if err != nil {
		return errs.NewExitError(1, "preparing the capability registry: "+err.Error())
	}

	code, err := tui.Run(tui.Config{
		Title:   "QYVORA / NZINGA",
		Version: version.String(),
		Banner:  tui.ToolBanner("NZINGA", "Authorized Open-Source Intelligence Framework"),
		Runner:  runner,
		Out:     os.Stdout,
		// The tool's own progress output is discarded rather than shown: it
		// is redrawn in place by the tool and would flicker underneath the
		// TUI's own frames. The transcript carries the same information as an
		// event stream, which the interface can lay out properly.
		Err:          nil,
		Capabilities: caps,
	})
	if err != nil {
		if tui.IsNotInteractive(err) {
			return root.Help()
		}
		return err
	}
	if code != 0 {
		return &exitStatusError{code: code}
	}
	return nil
}

// commandTUI returns the explicit form of the interactive command, so the TUI
// can be started without relying on the bare invocation.
func commandTUI() *cobra.Command {
	return &cobra.Command{
		Use:     "tui",
		Aliases: []string{"console"},
		Short:   "start the interactive terminal application",
		Long: "Start the QYVORA interactive terminal application.\n\n" +
			"Commands are entered at the prompt and executed through the same engine as\n" +
			"the one-shot CLI, with the structured event stream rendered in the session.\n" +
			"Ctrl+C stops the running command; Ctrl+D leaves.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTUI(cmd.Root(), cmd.Context())
		},
	}
}

// exitStatusError carries a non-zero exit code out of the TUI so the process
// still reports the status of the last command that ran.
type exitStatusError struct{ code int }

func (e *exitStatusError) Error() string {
	return fmt.Sprintf("last command exited with status %d", e.code)
}

// tuiCommands derives completion metadata from the live command tree.
//
// Reading it from Cobra rather than from a hand-written list means completion
// cannot drift away from the commands that actually exist. The adapter is
// necessary because the shared TUI deliberately does not depend on Cobra: which
// command framework a tool uses is that tool's decision, not the interface's.
func tuiCommands(root *cobra.Command) []tui.Command {
	return tui.CobraCommands(root)
}
