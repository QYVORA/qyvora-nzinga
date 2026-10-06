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
	"github.com/QYVORA/qyvora-nzinga/internal/search"
	"github.com/QYVORA/qyvora-nzinga/internal/session"
	"github.com/QYVORA/qyvora-nzinga/internal/target"
	"github.com/QYVORA/qyvora-nzinga/internal/version"
)

var app = newAppState()
var updateFlag bool

const appDescription = `nzinga is a terminal-first intelligence collection and OSINT framework for
authorized reconnaissance: collect from public sources, correlate entities
into claims, evaluate detections, and produce evidence-driven reports.

Usage modes:
  nzinga                                 start the interactive console
  nzinga assess --sim                    full pipeline against the offline demo dataset
  nzinga assess --target example.com     full pipeline against an authorized live target
  nzinga domain|organization|username|infrastructure <name>
                                         run the target-specific collection pipeline
  nzinga dork <domain>                   search-engine dorking over a domain (opt-in)
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
		if app.stdoutOwned && app.printer.Format() != output.FormatTerminal {
			// stdout must carry exactly one machine stream. With the event
			// JSONL stream owning stdout, a machine report format cannot share
			// it: use --events stderr, --events <file>, or --report <dir>.
			return errs.NewExitError(2, "cannot combine --events stdout with a machine report format; use --events stderr, --events <file>, or --report <dir>")
		}
		return nil
	},
	Args: func(_ *cobra.Command, args []string) error {
		if len(args) > 0 {
			return errs.NewExitError(2, fmt.Sprintf("unknown command %q (try 'nzinga --help')", args[0]))
		}
		return nil
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
	return ExecuteArgsContext(ctx, args)
}

// ExecuteArgsContext runs the root command with an explicit argument vector
// under a caller-supplied context and returns the process exit code.
//
// The interactive TUI needs this form. It runs commands in-process on its own
// goroutine and must be able to cancel a single execution without tearing down
// the process, so the work is driven by a context the caller owns rather than
// by process-wide signal handling. That distinction is what makes Ctrl+C cancel
// the operation instead of the interface.
func ExecuteArgsContext(ctx context.Context, args []string) int {
	rootCmd.SetArgs(args)

	// If --update is passed, route to the update subcommand regardless of
	// other positional arguments.
	for _, a := range args {
		if a == "--update" || a == "-update" || a == "--update=true" {
			rootCmd.SetArgs([]string{"update"})
			break
		}
	}

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
	// The default action opens the interactive TUI. It is assigned here rather
	// than in the rootCmd literal because Go's initialisation dependency
	// analysis follows references through function bodies: runTUI reaches
	// rootCmd, so naming it inside rootCmd's own initialiser is a cycle, while
	// init() is exempt from that analysis.
	rootCmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return runTUI(cmd.Root(), cmd.Context())
	}
	// "console" is kept as an alias on commandTUI so existing invocations and
	// documentation keep working; both now open the same interface.
	rootCmd.AddCommand(commandTUI())

	cobra.OnInitialize(initConfig)

	rootCmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return errs.NewExitError(2, err.Error())
	})

	pf := rootCmd.PersistentFlags()
	pf.BoolVar(&updateFlag, "update", false, "update the CLI to the latest official release")
	pf.StringVarP(&app.cfgFile, "config", "c", "", "config file (default $HOME/.config/qyvora/nzinga/config.yaml")
	pf.BoolVarP(&app.verbose, "verbose", "v", false, "verbose output")
	pf.BoolVarP(&app.quiet, "quiet", "q", false, "suppress non-error output")
	pf.StringVarP(&app.outputFmt, "output", "o", "", "output format: terminal, json, markdown, html, yaml")
	pf.BoolVar(&app.jsonOut, "json", false, "output in JSON format (shorthand for --output json)")
	pf.StringVar(&app.eventsF, "events", "", "emit a JSONL event stream to stdout, stderr, or a file path")
	pf.BoolVar(&app.dryRun, "dry-run", false, "resolve and print the collection plan without executing")

	pf.BoolP("authorized", "y", false, "confirm authorization scope non-interactively")

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
	rootCmd.AddCommand(newDorkCmd())
	rootCmd.AddCommand(newDorksCmd())

	rootCmd.SetVersionTemplate(fmt.Sprintf("nzinga %s\n", version.String()))
}

// initConfig loads configuration and initializes the shared logger, printer,
// target manager, session store and source registry. Failures are recorded as
// init errors so ExecuteArgs can report them without calling os.Exit.
func initConfig() {
	// The interactive TUI runs this command tree repeatedly in one process, so
	// every invocation must start from clean state. Without this reset a failure
	// recorded by one run is reported as the outcome of every later run:
	// initErr is set but never cleared, so a single bad invocation would make
	// the rest of the session exit 2.
	app.initErr = nil
	app.stdoutOwned = false

	v, err := config.Load(app.cfgFile)
	if err != nil {
		app.initErr = errs.WrapExitError(2, "loading config", err)
		return
	}
	app.cfg = v
	initLogger()
	initPrinter()
	app.targets = target.NewManager(v.GetString("target.state"))
	app.store = session.NewStore(v.GetString("session.dir"))
	app.dorks = loadDorkCatalog()
	app.reg = sources.NewRegistry(allSources()...)
	if app.eventsF != "" {
		if err := app.resolveEvents(rootCmd.Context()); err != nil {
			app.initErr = errs.WrapExitError(2, "configuring events", err)
			return
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
	// ANSI color is a terminal-only nicety: disable it when stdout is not an
	// interactive device or when the caller opts out via NO_COLOR, so no
	// escape sequences leak into redirected or piped output.
	color.NoColor = !stdoutIsTerminal() || os.Getenv("NO_COLOR") != ""
}

// stdoutIsTerminal reports whether standard output is an interactive
// character device.
func stdoutIsTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
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
		sources.NewAbuseIPDB(shared, app.cfg.GetString("sources.abuseipdb.token")),
		sources.NewSearch(app.cfg, shared, app.dorks),
		sources.NewSimulation(),
	}
}

// loadDorkCatalog loads the dork template catalog. If a custom wordlist is
// configured, it is merged with (or replaces) the embedded catalog. A catalog
// failure records an init error so the binary still starts but collection is refused.
func loadDorkCatalog() *search.DorkSet {
	customPath := app.cfg.GetString("sources.search.custom_wordlist_path")
	builtinEnabled := app.cfg.GetBool("sources.search.builtin_enabled")

	var set *search.DorkSet
	var err error

	if customPath != "" {
		set, err = search.LoadWithCustom(customPath, builtinEnabled)
	} else {
		set, err = search.LoadEmbedded()
	}

	if err != nil && app.initErr == nil {
		app.initErr = errs.WrapExitError(1, "loading dork catalog", err)
		return nil
	}
	return set
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