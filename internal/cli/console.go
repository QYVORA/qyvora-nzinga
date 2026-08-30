package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-nzinga/internal/version"
)

// nzingaConsole is the interactive, unified console.
type nzingaConsole struct {
	ctx     context.Context
	out     io.Writer
	ui      *consoleUI
	rl      *readline.Instance
	history []string
	cwd     string
	target  string
	profile string
}

func runConsole(ctx context.Context) error {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	c := &nzingaConsole{
		ctx:     ctx,
		out:     os.Stdout,
		ui:      newConsoleUI(os.Stdout),
		cwd:     cwd,
		target:  "example.com",
		profile: "standard",
	}

	if !consoleTTY(os.Stdin) {
		return c.runPlain()
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:       c.ui.Prompt("nzinga"),
		HistoryFile:  c.historyPath(),
		AutoComplete: readline.NewPrefixCompleter(c.completer()...),
	})
	if err != nil {
		_, _ = fmt.Fprintf(c.out, "line editing unavailable (%v); continuing in plain mode\n", err)
		return c.runPlain()
	}
	c.rl = rl
	defer func() { _ = rl.Close() }()

	c.ui.Banner("OSINT & intelligence collection framework")
	c.ui.BannerFoot(version.String())
	c.hud()
	c.ui.Status("*", "console ready; type 'help' for commands.")

	for {
		line, err := rl.Readline()
		if err != nil {
			if errors.Is(err, readline.ErrInterrupt) {
				continue
			}
			return nil // EOF / Ctrl-D
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		c.history = append(c.history, line)
		quit, e := c.exec(line)
		c.hud()
		if e != nil {
			c.ui.Err("%v", e)
		} else if quit {
			return nil
		}
	}
}

func (c *nzingaConsole) runPlain() error {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		c.history = append(c.history, line)
		quit, err := c.exec(line)
		if err != nil {
			_, _ = fmt.Fprintf(c.out, "error: %v\n", err)
		}
		if quit {
			return nil
		}
	}
	return sc.Err()
}

func (c *nzingaConsole) historyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".nzinga_history"
	}
	dir := filepath.Join(home, ".qyvora")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ".nzinga_history"
	}
	return filepath.Join(dir, "nzinga_history")
}

func (c *nzingaConsole) hud() {
	c.ui.HUD(c.target, c.profile, c.cwd, version.String())
}

func (c *nzingaConsole) completer() []readline.PrefixCompleterInterface {
	return []readline.PrefixCompleterInterface{
		readline.PcItem("assess"),
		readline.PcItem("discover"),
		readline.PcItem("domain"),
		readline.PcItem("organization"),
		readline.PcItem("username"),
		readline.PcItem("ip"),
		readline.PcItem("infrastructure"),
		readline.PcItem("analyze"),
		readline.PcItem("findings"),
		readline.PcItem("evidence"),
		readline.PcItem("graph"),
		readline.PcItem("report"),
		readline.PcItem("sources"),
		readline.PcItem("target"),
		readline.PcItem("capabilities"),
		readline.PcItem("tools"),
		readline.PcItem("updates"),
		readline.PcItem("version"),
		readline.PcItem("banner"),
		readline.PcItem("help"),
		readline.PcItem("clear"),
		readline.PcItem("history"),
		readline.PcItem("pwd"),
		readline.PcItem("cd"),
		readline.PcItem("use"),
		readline.PcItem("show"),
		readline.PcItem("status"),
		readline.PcItem("back"),
		readline.PcItem("run"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	}
}

func (c *nzingaConsole) exec(line string) (bool, error) {
	if strings.HasPrefix(line, "!") {
		cmdStr := strings.TrimSpace(strings.TrimPrefix(line, "!"))
		if cmdStr == "" {
			return false, errors.New("empty shell command after '!'")
		}
		c.runShell(cmdStr)
		return false, nil
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false, nil
	}
	name, args := fields[0], fields[1:]

	switch name {
	case "exit", "quit", "q", "bye":
		return true, nil
	case "help", "?":
		c.help()
		return false, nil
	case "clear", "cls":
		_, _ = fmt.Fprint(c.out, "\x1b[H\x1b[2J")
		return false, nil
	case "banner", "logo":
		c.ui.Banner("OSINT & intelligence collection framework")
		return false, nil
	case "version", "ver":
		printVersion(version.GetInfo())
		return false, nil
	case "history":
		for i, h := range c.history {
			fmt.Fprintf(c.out, "  %3d  %s\n", i+1, h)
		}
		return false, nil
	case "pwd":
		c.ui.KV("working directory", c.cwd)
		return false, nil
	case "cd":
		return false, c.cmdCd(args)
	case "shell", "sh":
		if len(args) == 0 {
			return false, errors.New("usage: shell <command>")
		}
		c.runShell(strings.Join(args, " "))
		return false, nil
	case "target", "tgt":
		return false, c.cmdTarget(args)
	case "use":
		if len(args) == 0 {
			return false, errors.New("usage: use <target value>")
		}
		c.target = args[0]
		c.ui.Status("*", "using target %s", c.target)
		return false, nil
	case "show", "status":
		c.ui.KV("console target", c.target)
		c.ui.KV("profile", c.profile)
		c.ui.KV("working directory", c.cwd)
		if cur := app.targets.Current(); cur != nil {
			c.ui.KV("saved target", cur.TypedName())
		}
		return false, nil
	case "back":
		return false, c.cmdCd([]string{".."})
	case "run":
		opts := targetFlagsFrom(simCommand())
		if len(args) == 0 {
			opts.value = c.target
		} else if v := firstTargetArg(args); v != "" {
			opts.value = v
		}
		sess, err := app.runPipeline(c.ctx, simCommand(), opts)
		if err != nil {
			return false, err
		}
		if sess != nil {
			return false, renderSession(c.ctx, sess)
		}
		return false, nil
	default:
		return c.execCommand(name, args)
	}
}

func (c *nzingaConsole) execCommand(name string, args []string) (bool, error) {
	sim := simCommand()
	switch name {
	case "assess", "scan":
		opts := targetFlagsFrom(sim)
		if v := firstTargetArg(args); v != "" {
			opts.value = v
		}
		return false, runCobraCollect(c.ctx, sim, opts)
	case "domain", "organization", "org", "username", "user", "ip", "infrastructure", "infra":
		typ := map[string]string{
			"domain": "domain", "organization": "organization", "org": "organization",
			"username": "username", "user": "username", "ip": "ip", "infrastructure": "infrastructure", "infra": "infrastructure",
		}[name]
		opts := targetFlagsFrom(sim)
		opts.typ = typ
		if v := firstTargetArg(args); v != "" {
			opts.value = v
		}
		return false, runCobraCollect(c.ctx, sim, opts)
	case "analyze", "rules":
		return false, runAnalyze(c.ctx, nil)
	case "findings", "finds":
		return false, runFindings(c.ctx)
	case "evidence", "ev":
		return false, runEvidence(c.ctx)
	case "graph", "relationships", "relationship":
		return false, runGraph(c.ctx)
	case "report":
		return false, runReport(c.ctx, "", "")
	case "sources":
		printSourcesTable()
		return false, nil
	case "capabilities", "caps", "tools":
		printCapabilitiesTable()
		return false, nil
	case "updates", "update":
		return false, runUpdates(c.ctx, false)
	default:
		return false, fmt.Errorf("unknown command %q (type 'help')", name)
	}
}

// runCobraCollect invokes the shared collection flow for console commands.
func runCobraCollect(ctx context.Context, cmd *cobra.Command, opts targetOptions) error {
	sess, err := app.runPipeline(ctx, cmd, opts)
	if err != nil {
		return err
	}
	if sess == nil {
		return nil
	}
	return renderSession(ctx, sess)
}

func (c *nzingaConsole) cmdCd(args []string) error {
	target := ""
	if len(args) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		target = home
	} else {
		target = args[0]
		if !filepath.IsAbs(target) {
			target = filepath.Join(c.cwd, target)
		}
	}
	target = filepath.Clean(target)
	info, err := os.Stat(target)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s: not a directory", target)
	}
	c.cwd = target
	c.ui.KV("cwd", c.cwd)
	return nil
}

func (c *nzingaConsole) cmdTarget(args []string) error {
	if len(args) == 0 {
		c.ui.KV("current target", c.target)
		c.ui.Status("*", "target selection: 'target set <value>' or use 'assess --sim' for the offline demo.")
		return nil
	}
	c.target = args[len(args)-1]
	c.ui.Status("+", "target set to: %s", c.target)
	return nil
}

func (c *nzingaConsole) runShell(cmdStr string) {
	cmd := exec.CommandContext(c.ctx, "sh", "-c", cmdStr)
	cmd.Dir = c.cwd
	cmd.Stdout = c.out
	cmd.Stderr = c.out
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		c.ui.Err("command failed: %v", err)
	}
}

func simCommand() *cobra.Command {
	cmd := &cobra.Command{}
	registerTargetFlags(cmd.Flags())
	_ = cmd.Flags().Set("sim", "true")
	return cmd
}

func consoleTTY(f *os.File) bool {
	return isTTY(f)
}

// firstTargetArg returns the first argument that is not a flag token, so
// typing "assess --sim example.com" picks the target value out of the flags.
func firstTargetArg(args []string) string {
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

func (c *nzingaConsole) help() {
	c.ui.Section("Core Commands")
	coreRows := [][]string{
		{"assess", "run the full intelligence pipeline (offline demo default)"},
		{"domain", "collect and analyze a domain target"},
		{"organization", "collect and analyze an organization target"},
		{"username", "collect and analyze a username target"},
		{"ip", "collect and analyze an IP target"},
		{"infrastructure", "collect and analyze an infrastructure target"},
		{"analyze", "review findings and risk for the latest session"},
		{"findings", "list rule findings from the latest session"},
		{"evidence", "list evidence artifacts from the latest session"},
		{"graph", "render the relationship graph from the latest session"},
		{"report", "render the structured intelligence report"},
	}
	c.ui.Table([]string{"COMMAND", "DESCRIPTION"}, coreRows)

	c.ui.Section("Session & Utilities")
	utilRows := [][]string{
		{"target", "view or set current collection target"},
		{"sources", "list intelligence sources and capabilities"},
		{"banner", "display the canonical brand ASCII banner"},
		{"capabilities", "list machine-readable capabilities"},
		{"updates", "check for official QYVORA releases"},
		{"version", "print version and runtime build info"},
		{"history", "show session command history"},
		{"pwd / cd", "view or navigate local filesystem"},
		{"shell / !cmd", "execute a host shell command"},
		{"clear", "clear console screen"},
		{"exit / quit", "leave the interactive console"},
	}
	c.ui.Table([]string{"COMMAND", "DESCRIPTION"}, utilRows)
	c.ui.Rule()
}
