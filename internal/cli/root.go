package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-nzinga/internal/config"
	errs "github.com/QYVORA/qyvora-nzinga/internal/errors"
	"github.com/QYVORA/qyvora-nzinga/internal/intelligence/sources"
	"github.com/QYVORA/qyvora-nzinga/internal/logger"
	"github.com/QYVORA/qyvora-nzinga/internal/output"
	"github.com/QYVORA/qyvora-nzinga/internal/session"
	"github.com/QYVORA/qyvora-nzinga/internal/target"
	"github.com/QYVORA/qyvora-nzinga/internal/version"
)

var app = newAppState()

const appDescription = `nzinga is a terminal-first intelligence collection and OSINT framework for
authorized reconnaissance: collect from public sources, correlate entities
into claims, evaluate detections, and produce evidence-driven reports.

Usage modes:
  nzinga                                 start the interactive console
  nzinga assess --sim                    full pipeline against the offline demo dataset
  nzinga assess --target example.com     full pipeline against an authorized live target
  nzinga domain|organization|username|infrastructure <name>
                                         run the target-specific collection pipeline
  nzinga sources list|show               list intelligence sources
  nzinga findings|evidence|graph         inspect the latest session
  nzinga report                          render the latest assessment report
  nzinga target set|list|show            manage targets
  nzinga capabilities                    list the machine-readable tool contract
  nzinga updates                         check for and install updates

Live collection requires explicit target authorization (-y/--authorized or
QYVORA_AUTHORIZED=true). nzinga is scoped, reversible and intended for use
only on targets you are authorized to evaluate.`

var rootCmd = &cobra.Command{
	Use:           "nzinga",
	Short:         "Authorized OSINT and intelligence collection framework",
	Long:          appDescription,
	Version:       version.String(),
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		if app.initErr != nil {
			return errs.NewExitError(2, app.initErr.Error())
		}
		return nil
	},
	Args: func(_ *cobra.Command, args []string) error {
		if len(args) > 0 {
			return errs.NewExitError(2, fmt.Sprintf("unknown command %q (try 'nzinga --help')", args[0]))
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runConsole(cmd.Context())
	},
}

// Execute runs the root command against os.Args and returns the process exit
// code. It never calls os.Exit itself so callers control termination.
func Execute() int {
	return ExecuteArgs(os.Args[1:])
}

// ExecuteArgs runs the root command with an explicit argument vector and
// returns the process exit code.
func ExecuteArgs(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	rootCmd.SetContext(ctx)
	rootCmd.SetArgs(args)

	if err := rootCmd.Execute(); err != nil {
		var exitErr *errs.ExitError
		if errors.As(err, &exitErr) {
			fmt.Fprintln(os.Stderr, wrapErr(exitErr.Message))
			if exitErr.Cause != nil {
				fmt.Fprintln(os.Stderr, "  "+exitErr.Cause.Error())
			}
			return exitErr.Code
		}
		fmt.Fprintln(os.Stderr, wrapErr(err.Error()))
		return 1
	}
	if app.initErr != nil {
		fmt.Fprintln(os.Stderr, wrapErr(app.initErr.Error()))
		return 2
	}
	return 0
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return errs.NewExitError(2, err.Error())
	})

	pf := rootCmd.PersistentFlags()
	pf.StringVarP(&app.cfgFile, "config", "c", "", "config file (default $HOME/.config/qyvora/nzinga/config.yaml)")
	pf.BoolVarP(&app.verbose, "verbose", "v", false, "verbose output")
	pf.BoolVarP(&app.quiet, "quiet", "q", false, "suppress non-error output")
	pf.StringVarP(&app.outputFmt, "output", "o", "", "output format: terminal, json, markdown, html, yaml")
	pf.BoolVar(&app.jsonOut, "json", false, "output in JSON format (shorthand for --output json)")
	pf.StringVar(&app.eventsF, "events", "", "emit a JSONL event stream to stdout, stderr, or a file path")
	pf.BoolVar(&app.dryRun, "dry-run", false, "resolve and print the collection plan without executing")

	rootCmd.PersistentFlags().BoolP("authorized", "y", false, "confirm authorization scope non-interactively")

	registerTargetFlags(pf)

	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newCapabilitiesCmd())
	rootCmd.AddCommand(newCompletionCmd())
	rootCmd.AddCommand(newUpdatesCmd())
	rootCmd.AddCommand(newTargetCmd())
	rootCmd.AddCommand(newAssessCmd())
	rootCmd.AddCommand(newDiscoverCmd())
	rootCmd.AddCommand(newCollectCmd())
	rootCmd.AddCommand(newFindingsCmd())
	rootCmd.AddCommand(newEvidenceCmd())
	rootCmd.AddCommand(newGraphCmd())
	rootCmd.AddCommand(newRelationshipCmd())
	rootCmd.AddCommand(newAnalyzeCmd())
	rootCmd.AddCommand(newReportCmd())
	rootCmd.AddCommand(newSourcesCmd())

	rootCmd.SetVersionTemplate(fmt.Sprintf("nzinga %s\n", version.String()))
}

// initConfig loads configuration and initializes the shared logger, printer,
// target manager, session store and source registry.
func initConfig() {
	v, err := config.Load(app.cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}
	app.cfg = v
	initLogger()
	initPrinter()
	app.targets = target.NewManager(v.GetString("target.state"))
	app.store = session.NewStore(v.GetString("session.dir"))
	app.reg = sources.NewRegistry(allSources()...)
	if app.eventsF != "" {
		if err := app.resolveEvents(rootCmd.Context()); err != nil {
			fmt.Fprintf(os.Stderr, "error configuring events: %v\n", err)
			os.Exit(1)
		}
	}
}

func initLogger() {
	app.log = logger.New()
	app.log.SetLevel(logger.ParseLevel(app.cfg.GetString("log.level")))
	if app.verbose || app.cfg.GetBool("verbose") {
		app.log.SetVerbose(true)
	}
	if app.quiet || app.cfg.GetBool("quiet") {
		app.log.SetQuiet(true)
	}
}

func initPrinter() {
	app.printer = output.New()
	format := "terminal"
	switch {
	case app.outputFmt != "":
		format = app.outputFmt
	case app.jsonOut:
		format = "json"
	case app.cfg.GetBool("json"):
		format = "json"
	case app.cfg.IsSet("output"):
		if v, ok := app.cfg.Get("output").(string); ok && v != "" {
			format = v
		}
	}
	parsed, err := output.ParseFormat(format)
	if err != nil {
		app.initErr = errs.WrapExitError(2, "invalid --output format", err)
		return
	}
	app.printer.SetFormat(parsed)
}

// allSources returns the built-in collectors in registry order.
func allSources() []sources.Source {
	shared, err := buildSharedClient()
	if err != nil && app.initErr == nil {
		app.initErr = errs.WrapExitError(1, "initializing collection client", err)
	}
	whoisPort := app.cfg.GetInt("sources.whois.port")
	if whoisPort <= 0 {
		whoisPort = 43
	}
	return []sources.Source{
		sources.NewCrtSh(shared),
		sources.NewDNS(),
		sources.NewWhois(whoisPort),
		sources.NewGitHub(shared, app.cfg.GetString("sources.github.token")),
		sources.NewSimulation(),
	}
}

// buildSharedClient constructs the hardened HTTP client from configuration.
func buildSharedClient() (*sources.Client, error) {
	return sources.NewClient(sources.ClientOptions{
		Timeout:          config.Timeout(app.cfg),
		UserAgent:        config.UserAgent(app.cfg),
		MaxResponseBytes: config.MaxResponseBytes(app.cfg),
		FollowRedirects:  config.FollowRedirects(app.cfg),
		Proxy:            app.cfg.GetString("collection.http_proxy"),
		MaxRetries:       app.cfg.GetInt("collection.max_retries"),
		RateLimitPerSec:  float64(app.cfg.GetInt("collection.rate_limit_per_second")),
	})
}

func wrapErr(msg string) string {
	return color.New(color.FgRed, color.Bold).Sprint("Error: ") + msg
}
