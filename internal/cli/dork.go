package cli

import (
	"context"
	"strings"

	"github.com/spf13/cobra"

	errs "github.com/QYVORA/qyvora-nzinga/internal/errors"
	"github.com/QYVORA/qyvora-nzinga/internal/search"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// newDorkCmd runs a dorking pass over a target through the full pipeline. It
// is the sanctioned way to activate the opt-in search source without changing
// a config file.
func newDorkCmd() *cobra.Command {
	var category, provider string
	var maxQueries int
	cmd := &cobra.Command{
		Use:     "dork <domain>",
		Aliases: []string{"dorking"},
		Short:   "Run search-engine dorking over a domain (opt-in search source)",
		Long: `Run the full pipeline with the search source enabled against one domain.

Dorking is opt-in and curbed: only the query templates in the embedded catalog
run, bounded by sources.search.max_queries, and results are recorded as
unverified references, never as confirmed facts. Live collection needs a
sanctioned provider (--provider api plus search.endpoint, or --provider
simulation for the offline dataset). This tool never bypasses CAPTCHA or
anti-automation controls; challenged surfaces are reported instead.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := targetFlagsFrom(cmd)
			if len(args) == 1 && opts.value == "" {
				opts.value = args[0]
			}
			opts.typ = "domain"
			if strings.TrimSpace(opts.value) == "" {
				return errs.NewExitError(2, "dork requires a domain target: nzinga dork example.com")
			}
			if provider != "" {
				app.cfg.Set("search.provider", provider)
			}
			if category != "" {
				app.cfg.Set("sources.search.categories", category)
			}
			if maxQueries > 0 {
				app.cfg.Set("sources.search.max_queries", maxQueries)
			}
			sess, err := runDorkPipeline(ctxOf(cmd), cmd, opts)
			if err != nil {
				return err
			}
			if sess == nil {
				return nil
			}
			return renderSession(ctxOf(cmd), sess)
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "", "search provider: simulation or api (default config search.provider)")
	cmd.Flags().StringVar(&category, "category", "", "comma-separated categories: "+strings.Join(categoryNames(), ", "))
	cmd.Flags().IntVar(&maxQueries, "max-queries", 0, "cap the number of queries (default config sources.search.max_queries)")
	registerTargetFlags(cmd.Flags())
	return cmd
}

// newDorksCmd exposes the embedded query template catalog.
func newDorksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dorks",
		Short: "List the embedded dork query templates by category",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List dork templates grouped by category",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			printDorksList()
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "show <category|target>",
		Short: "Show one category's templates, or the rendered queries for a target",
		Args:  cobra.MaximumNArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			printDorksShow(args)
		},
	})
	return cmd
}

func printDorksList() {
	set := app.dorks
	if set == nil || set.Count() == 0 {
		app.emitf("no dork templates loaded")
		return
	}
	switch app.printerFormat() {
	case outputFormatJSON, outputFormatYAML:
		app.printer.Print(struct {
			Categories []search.Category `json:"categories"`
		}{Categories: set.Categories()})
		return
	}
	for _, c := range set.Categories() {
		templates := set.InCategory(c)
		app.emitf("%s (%d)", c, len(templates))
		for _, d := range templates {
			app.emitf("  %-24s %s", d.ID, d.Name)
		}
		app.emitf("")
	}
}

func printDorksShow(args []string) {
	set := app.dorks
	if set == nil || set.Count() == 0 {
		app.emitf("no dork templates loaded")
		return
	}
	if len(args) == 0 {
		printDorksList()
		return
	}
	arg := strings.TrimSpace(args[0])

	// A category argument lists the templates in that category.
	if cat, ok := search.ParseCategory(arg); ok {
		templates := set.InCategory(cat)
		app.emitf("%s (%d)", cat, len(templates))
		for _, d := range templates {
			app.emitf("  %-24s %s", d.ID, d.Name)
			if d.Description != "" {
				app.emitf("    %s", d.Description)
			}
			app.emitf("    query: %s", d.Query)
		}
		return
	}

	// Anything else is treated as a target value: render the queries for it
	// without executing them (a dry-run of the template catalog).
	queries, err := set.ForTarget(arg, nil, 0)
	if err != nil {
		app.emitf("error: %v", err)
		return
	}
	app.emitf("rendered queries for %q (%d):", arg, len(queries))
	for _, q := range queries {
		app.emitf("  [%s] %-12s %s", q.Category, q.Dork.ID, q.Query)
	}
}

func categoryNames() []string {
	out := make([]string, 0, len(search.AllCategories))
	for _, c := range search.AllCategories {
		out = append(out, string(c))
	}
	return out
}

// runDorkPipeline enables the search source for exactly one pipeline run and
// restores the configuration afterwards, so a console `dork` cannot leak the
// setting into a later `assess`/`domain` command. It always runs only the
// search source (collect.search_only) regardless of the target profile.
func runDorkPipeline(ctx context.Context, cmd *cobra.Command, opts targetOptions) (*models.Session, error) {
	app.cfg.Set("sources.search.enabled", true)
	app.cfg.Set("collect.search_only", true)
	sess, err := app.runPipeline(ctx, cmd, opts)
	app.cfg.Set("collect.search_only", false)
	app.cfg.Set("sources.search.enabled", false)
	return sess, err
}
