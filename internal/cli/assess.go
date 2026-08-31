package cli

import (
	"context"
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-nzinga/internal/config"
	"github.com/QYVORA/qyvora-nzinga/internal/core"
	errs "github.com/QYVORA/qyvora-nzinga/internal/errors"
	"github.com/QYVORA/qyvora-nzinga/internal/pipeline"
	"github.com/QYVORA/qyvora-nzinga/internal/reporting"
	"github.com/QYVORA/qyvora-nzinga/internal/session"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

func newAssessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "assess [target]",
		Aliases: []string{"scan"},
		Short:   "Run the full intelligence pipeline: discover→collect→normalize→correlate→analyze→validate→report",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := targetFlagsFrom(cmd)
			if len(args) == 1 && opts.value == "" {
				opts.value = args[0]
			}
			sess, err := app.runPipeline(ctxOf(cmd), cmd, opts)
			if err != nil {
				return err
			}
			if sess == nil {
				return nil
			}
			return renderSession(ctxOf(cmd), sess)
		},
	}
	registerTargetFlags(cmd.Flags())
	return cmd
}

// newDiscoverCmd runs only the DISCOVER stage: target resolution and
// validation. It shares the pipeline's discover implementation.
func newDiscoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "discover [target]",
		Aliases: []string{"find"},
		Short:   "Run the discovery stage only: resolve and validate the target",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := targetFlagsFrom(cmd)
			if len(args) == 1 && opts.value == "" {
				opts.value = args[0]
			}
			sess, err := app.runPipeline(ctxOf(cmd), cmd, opts, pipeline.StageDiscover)
			if err != nil {
				return err
			}
			if sess == nil {
				return nil
			}
			return renderSession(ctxOf(cmd), sess)
		},
	}
	registerTargetFlags(cmd.Flags())
	return cmd
}

func newCollectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect intelligence for a target type",
	}
	cmd.AddCommand(newTargetCollectCmd("domain", "domain", "network"))
	cmd.AddCommand(newTargetCollectCmd("organization", "org", "organization"))
	cmd.AddCommand(newTargetCollectCmd("username", "user", "username"))
	cmd.AddCommand(newTargetCollectCmd("ip", "ip", "ip"))
	cmd.AddCommand(newTargetCollectCmd("infrastructure", "infra", "infrastructure"))
	return cmd
}

func newTargetCollectCmd(name, alias, typ string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     name + " <value>",
		Aliases: []string{alias},
		Short:   "Collect and analyze a " + typ + " target",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := targetFlagsFrom(cmd)
			if opts.value == "" && len(args) == 1 {
				opts.value = args[0]
			}
			opts.typ = typ
			sess, err := app.runPipeline(ctxOf(cmd), cmd, opts)
			if err != nil {
				return err
			}
			if sess == nil {
				return nil
			}
			return renderSession(ctxOf(cmd), sess)
		},
	}
	registerTargetFlags(cmd.Flags())
	return cmd
}

func newAnalyzeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "analyze",
		Aliases: []string{"rules"},
		Short:   "Re-run the rule engine and risk assessment over the latest session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAnalyze(ctxOf(cmd), cmd)
		},
	}
}

func newFindingsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "findings",
		Aliases: []string{"finds"},
		Short:   "List findings from the latest session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFindings(ctxOf(cmd))
		},
	}
}

func newEvidenceCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "evidence",
		Aliases: []string{"ev"},
		Short:   "List evidence collected in the latest session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEvidence(ctxOf(cmd))
		},
	}
}

func newGraphCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "graph",
		Aliases: []string{"relationships"},
		Short:   "Render the relationship graph from the latest session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGraph(ctxOf(cmd))
		},
	}
}

// newRelationshipCmd groups the relationship surface: graph renders the
// full entity graph, show summarizes the relationship counts and types.
func newRelationshipCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relationship",
		Short: "Inspect the intelligence relationship graph of the latest session",
	}
	cmd.AddCommand(&cobra.Command{
		Use:     "graph",
		Aliases: []string{"edges"},
		Short:   "Render the relationship graph from the latest session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGraph(ctxOf(cmd))
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Summarize relationship types and counts from the latest session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRelationshipSummary(ctxOf(cmd))
		},
	})
	return cmd
}

// runRelationshipSummary prints a stable tally of relationship types in the
// latest session's graph.
func runRelationshipSummary(ctx context.Context) error {
	_ = ctx
	sess, err := latestSession()
	if err != nil {
		return err
	}
	counts := map[models.RelationshipType]int{}
	for _, e := range sess.Edges {
		counts[e.Type]++
	}
	types := make([]models.RelationshipType, 0, len(counts))
	for t := range counts {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	app.emitf("%d relationships across %d types:", len(sess.Edges), len(types))
	for _, t := range types {
		app.emitf("  %-16s %d", t, counts[t])
	}
	return nil
}

func newReportCmd() *cobra.Command {
	var format string
	var out string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render an intelligence report from the latest session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReport(ctxOf(cmd), format, out)
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "", "terminal, markdown, html, json, yaml")
	cmd.Flags().StringVar(&out, "out", "", "write report to file (default stdout)")
	return cmd
}

// runAnalyze renders the latest session's findings and risk.
func runAnalyze(ctx context.Context, cmd *cobra.Command) error {
	sess, err := latestSession()
	if err != nil {
		return err
	}
	return renderSession(ctx, sess)
}

func runFindings(ctx context.Context) error {
	sess, err := latestSession()
	if err != nil {
		return err
	}
	return renderFindings(sess)
}

func runEvidence(ctx context.Context) error {
	sess, err := latestSession()
	if err != nil {
		return err
	}
	return renderEvidence(sess)
}

func runGraph(ctx context.Context) error {
	sess, err := latestSession()
	if err != nil {
		return err
	}
	return renderGraph(sess)
}

func runReport(ctx context.Context, format, out string) error {
	sess, err := latestSession()
	if err != nil {
		return err
	}
	if format == "" {
		format = app.printerFormat()
	}
	return writeReport(sess, format, out)
}

func newSourcesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sources",
		Short: "List intelligence sources and their capabilities",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List all sources",
		Run: func(_ *cobra.Command, _ []string) {
			printSourcesTable()
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show the complete source catalog",
		Run: func(_ *cobra.Command, _ []string) {
			printSourcesFull()
		},
	})
	return cmd
}

// latestSession loads the most recently saved session.
func latestSession() (*models.Session, error) {
	ids, err := app.store.List()
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errNoSession
	}
	return app.store.Load(ids[0])
}

// runPipeline resolves the target, runs the pipeline (optionally stopping
// after a single stage), persists the session, and returns it. A nil session
// with a nil error means a dry-run.
func (a *appState) runPipeline(ctx context.Context, cmd *cobra.Command, opts targetOptions, until ...string) (*models.Session, error) {
	t, err := a.establishTarget(cmd, opts)
	if err != nil {
		return nil, err
	}
	if a.dryRun {
		return a.planRun(cmd, t, opts)
	}

	profile := opts.profile
	if profile == "" {
		profile = a.cfg.GetString("profile")
	}
	if !config.IsValidProfile(profile) {
		return nil, errs.NewExitError(2, fmt.Sprintf("unknown profile %q (valid: %s)", profile, joinProfiles()))
	}
	t.Profile = profile

	if t.ID == "" {
		t.ID = models.NewID("tgt")
	}
	sess := session.Begin(t)
	sess.OutputDir = a.cfg.GetString("report.dir")
	sess.Target = t.TypedName()

	env := &core.Env{
		Target:   t,
		Session:  sess,
		Registry: a.reg,
		Config:   a.cfg,
		Log:      a.log,
		Events:   a.eventStream,
		Offline:  opts.sim,
	}
	runner := &pipeline.Runner{}
	var runErr error
	if len(until) > 0 && until[0] != "" {
		runErr = runner.RunUntil(ctx, env, until[0])
	} else {
		runErr = runner.Run(ctx, env)
	}
	if runErr != nil {
		return sess, errs.WrapExitError(1, "assessment failed", runErr)
	}
	if _, err := a.persistSession(sess); err != nil {
		return sess, errs.WrapExitError(1, "persisting session", err)
	}
	return sess, nil
}

// planRun prints the sources that would run without touching the network.
func (a *appState) planRun(cmd *cobra.Command, t *models.Target, opts targetOptions) (*models.Session, error) {
	ids := []string(nil)
	var plan []models.Source
	switch t.Type {
	case models.TargetDomain, models.TargetInfrastructure:
		plan = a.reg.Plan(a.cfg, ids, t.Authorized())
	case models.TargetUsername, models.TargetOrganization:
		sel, err := a.reg.Select([]string{"github", "simulation"})
		if err == nil {
			for _, s := range sel {
				plan = append(plan, s.Describe())
			}
		}
	case models.TargetIP:
		if s, ok := a.reg.Find("simulation"); ok {
			plan = append(plan, s.Describe())
		}
	}
	a.emitf("dry-run: would collect against %s (offline=%v)", t.TypedName(), opts.sim)
	a.emitf("  profile: %s", t.Profile)
	for _, s := range plan {
		a.emitf("  source: %-12s %s", s.ID, s.Name)
	}
	return nil, nil
}

func (a *appState) printerFormat() string {
	return string(a.printer.Format())
}

func ctxOf(cmd *cobra.Command) context.Context {
	if cmd == nil || cmd.Context() == nil {
		return context.Background()
	}
	return cmd.Context()
}

func joinProfiles() string {
	out := ""
	for i, p := range config.Profiles {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// writeReport renders a session to a file or stdout.
func writeReport(sess *models.Session, format, out string) error {
	f, err := reporting.ParseFormat(format)
	if err != nil {
		return errs.NewExitError(2, err.Error())
	}
	content, err := reporting.Render(sess, f)
	if err != nil {
		return errs.WrapExitError(1, "rendering report", err)
	}
	if out == "" {
		_, _ = fmt.Fprint(app.printer.Writer(), content)
		return nil
	}
	return writeFile(out, []byte(content), 0o644)
}
