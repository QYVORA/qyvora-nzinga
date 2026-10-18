package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-script/ast"
	"github.com/QYVORA/qyvora-script/binding"
	"github.com/QYVORA/qyvora-script/interpreter"
	"github.com/QYVORA/qyvora-script/parser"

	"github.com/QYVORA/qyvora-nzinga/internal/capabilities"
	errs "github.com/QYVORA/qyvora-nzinga/internal/errors"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// newScriptCmd adds the flat `script` utility that runs the shared
// qyvora-script engine (ARCH-004 Part C). `script run <file>` executes a
// script; `script build <file>` prints a dry-run plan. A bare `script <file>`
// runs the file for convenience.
func newScriptCmd() *cobra.Command {
	run := func(dryRun bool) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			return runScriptFile(cmd, args[0], dryRun)
		}
	}
	cmd := &cobra.Command{
		Use:   "script <file>",
		Short: "run a .qs script with the shared scripting engine",
		Args:  cobra.ExactArgs(1),
		RunE:  run(false),
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "run <file>",
			Short: "execute a script file",
			Args:  cobra.ExactArgs(1),
			RunE:  run(false),
		},
		&cobra.Command{
			Use:   "build <file>",
			Short: "validate a script file and print a dry-run plan",
			Args:  cobra.ExactArgs(1),
			RunE:  run(true),
		},
	)
	return cmd
}

// runScriptFile parses (build) or executes (run) a script against nzinga's
// binding.
func runScriptFile(cmd *cobra.Command, path string, dryRun bool) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading script: %w", err)
	}
	prog, err := parser.Parse(string(src))
	if err != nil {
		return errs.NewExitError(2, err.Error())
	}
	if dryRun {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "script plan "+path)
		for _, line := range ast.Describe(prog) {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  -", line)
		}
		return nil
	}
	b := &scriptBinding{
		ctx:   ctxOf(cmd),
		allow: allowShellOut,
		cfg:   map[string]string{},
	}
	engine := interpreter.NewEngine(b)
	engine.Events = os.Stderr
	if err := engine.RunProgram(prog); err != nil {
		return errs.NewExitError(2, err.Error())
	}
	return nil
}

// scriptBinding implements binding.Binding against nzinga's intelligence
// pipeline. Every recognised module id runs the full pipeline (the collection
// sources, normalisation, correlation and analysis the id belongs to are all
// part of one assessment); unknown ids are refused.
type scriptBinding struct {
	ctx   context.Context
	allow bool
	cfg   map[string]string
	last  *models.Session
}

var _ binding.Binding = (*scriptBinding)(nil)

// Capabilities lists the whole-pipeline "assess" entry plus every capability
// in nzinga's machine contract.
func (b *scriptBinding) Capabilities() []string {
	tools := capabilities.New(app.reg.List())
	ids := make([]string, 0, 1+len(tools))
	ids = append(ids, "assess")
	for _, t := range tools {
		ids = append(ids, t.ID)
	}
	return ids
}

// AllowShellOut reports whether exec/run.cmd may run: only with the explicit
// flag or the shared opt-in environment variable.
func (b *scriptBinding) AllowShellOut() bool { return b.allow || shellOutEnv() }

func shellOutEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(interpreter.AllowShellOutEnv))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Call dispatches one engine capability invocation.
func (b *scriptBinding) Call(capabilityID string, args []binding.Value) (binding.Value, error) {
	switch capabilityID {
	case binding.CapEcho:
		_, _ = fmt.Fprintln(os.Stdout, asStr(args, 0))
		return nil, nil

	case binding.CapSetConfig:
		b.cfg[asStr(args, 0)] = asStr(args, 1)
		return nil, nil

	case binding.CapGetConfig:
		return b.cfg[asStr(args, 0)], nil

	case binding.CapStart:
		return nil, b.start(asStr(args, 0))

	case binding.CapStop, binding.CapIsRunning:
		if capabilityID == binding.CapIsRunning {
			return false, nil
		}
		return nil, nil

	case binding.CapShow:
		return nil, b.show(asStr(args, 0))

	case binding.CapReport:
		return nil, b.report(asStr(args, 0))

	case binding.CapProp:
		return b.prop(asStr(args, 0)), nil

	case binding.CapExec:
		return nil, b.exec(asStr(args, 0))
	}
	return nil, fmt.Errorf("unknown capability %q", capabilityID)
}

// start resolves a target and runs the intelligence pipeline for a module id.
func (b *scriptBinding) start(id string) error {
	if id != "" && id != "assess" && !hasCapability(id) {
		return fmt.Errorf("unknown module %q", id)
	}
	return b.run()
}

// run builds the target options and runs the full pipeline, capturing the
// session for $(...) interpolation.
func (b *scriptBinding) run() error {
	sim := isTrue(b.cfg["assess.sim"]) || isTrue(b.cfg["sim"])
	opts := targetOptions{
		value:   firstNonEmpty(b.cfg["assess.target"], b.cfg["target"]),
		typ:     firstNonEmpty(b.cfg["assess.type"], b.cfg["type"]),
		profile: firstNonEmpty(b.cfg["assess.profile"], b.cfg["profile"]),
		sim:     sim,
	}
	// A bare command carries the authorization flag nzinga's live target path
	// reads; the offline simulation needs none.
	cmd := &cobra.Command{}
	cmd.Flags().Bool("authorized", isTrue(b.cfg["assess.authorized"]), "")
	sess, err := app.runPipeline(b.ctx, cmd, opts)
	if err != nil {
		return err
	}
	b.last = sess
	if sess != nil {
		return renderSession(b.ctx, sess)
	}
	return nil
}

// show prints capability metadata for a module/capability id.
func (b *scriptBinding) show(id string) error {
	tools := capabilities.New(app.reg.List())
	rows := make([][]string, 0, len(tools)+1)
	if id == "assess" || id == "" {
		rows = append(rows, []string{"assess", "run the full intelligence pipeline", "analysis"})
	}
	for _, t := range tools {
		if id == "" || t.ID == id {
			rows = append(rows, []string{t.ID, t.Name, t.Category})
		}
	}
	if len(rows) == 0 {
		return fmt.Errorf("unknown module %q", id)
	}
	app.printer.PrintTable([]string{"capability", "name", "category"}, rows)
	return nil
}

// report writes a JSON session report for the most recent run.
func (b *scriptBinding) report(path string) error {
	if b.last == nil {
		return fmt.Errorf("no assessment to report; run a module first")
	}
	if path == "" {
		path = "nzinga-report.json"
	}
	data, err := json.MarshalIndent(b.last, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(app.printer.Writer(), "report written to "+path)
	return nil
}

// prop resolves live properties for $(...) interpolation from the last run.
func (b *scriptBinding) prop(name string) binding.Value {
	s := b.last
	if s == nil {
		return nil
	}
	switch name {
	case "session.id", "result.id":
		return s.ID
	case "session.target", "result.target":
		return s.Target
	case "result.profile":
		return s.Profile
	case "result.domains":
		return fmt.Sprintf("%d", len(s.Domains))
	case "result.hostnames":
		return fmt.Sprintf("%d", len(s.Hostnames))
	case "result.ips":
		return fmt.Sprintf("%d", len(s.IPs))
	case "result.observations":
		return fmt.Sprintf("%d", len(s.Observations))
	case "result.claims":
		return fmt.Sprintf("%d", len(s.Claims))
	case "result.findings":
		return fmt.Sprintf("%d", len(s.Findings))
	case "result.evidence":
		return fmt.Sprintf("%d", len(s.Evidence))
	case "result.risk_score":
		return fmt.Sprintf("%d", s.RiskScore)
	case "result.risk_level":
		return s.RiskLevel
	}
	return nil
}

// exec runs a one-shot nzinga command line. The interpreter only reaches here
// after AllowShellOut reported true.
func (b *scriptBinding) exec(line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if code := ExecuteArgs(strings.Fields(line)); code != 0 {
		return fmt.Errorf("command exited with code %d", code)
	}
	return nil
}

// hasCapability reports whether id is a registered nzinga capability.
func hasCapability(id string) bool {
	for _, t := range capabilities.New(app.reg.List()) {
		if t.ID == id {
			return true
		}
	}
	return false
}

func asStr(args []binding.Value, i int) string {
	if i >= len(args) || args[i] == nil {
		return ""
	}
	if s, ok := args[i].(string); ok {
		return s
	}
	return fmt.Sprintf("%v", args[i])
}

func isTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
