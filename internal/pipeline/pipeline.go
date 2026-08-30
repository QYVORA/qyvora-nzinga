// Package pipeline runs the nzinga intelligence pipeline for one target. The
// stages are fixed and ordered: DISCOVER -> COLLECT -> NORMALIZE -> CORRELATE
// -> ANALYZE -> VALIDATE -> REPORT. Each stage emits stage.started and
// stage.completed events with the work it actually performed; a stage never
// fabricates output, and failures degrade honestly (a failing source is
// recorded, the rest of the run continues).
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-nzinga/internal/core"
	"github.com/QYVORA/qyvora-nzinga/internal/events"
	"github.com/QYVORA/qyvora-nzinga/internal/intelligence/correlation"
	"github.com/QYVORA/qyvora-nzinga/internal/intelligence/domain"
	"github.com/QYVORA/qyvora-nzinga/internal/intelligence/normalization"
	"github.com/QYVORA/qyvora-nzinga/internal/intelligence/relationships"
	"github.com/QYVORA/qyvora-nzinga/internal/reporting"
	"github.com/QYVORA/qyvora-nzinga/internal/risk"
	"github.com/QYVORA/qyvora-nzinga/internal/rules"
	"github.com/QYVORA/qyvora-nzinga/internal/rules/builtin"
	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// Stage identifiers in pipeline order.
const (
	StageDiscover  = "discover"
	StageCollect   = "collect"
	StageNormalize = "normalize"
	StageCorrelate = "correlate"
	StageAnalyze   = "analyze"
	StageValidate  = "validate"
	StageReport    = "report"
)

// StageOrder is the fixed execution order.
var StageOrder = []string{
	StageDiscover, StageCollect, StageNormalize, StageCorrelate,
	StageAnalyze, StageValidate, StageReport,
}

// ErrInvalidIPTarget is returned when an ip target is not a valid IP literal.
var ErrInvalidIPTarget = errors.New("ip target is not a valid literal address")

// Runner executes the pipeline against a core environment.
type Runner struct{}

// Run performs every stage in order. It records per-stage work in the session
// and in the event stream. The first fatal error stops the run; collection
// errors are informational and do not abort the whole assessment.
func (r *Runner) Run(ctx context.Context, env *core.Env) error {
	return r.runUntil(ctx, env, "")
}

// RunDiscover runs only the DISCOVER stage, then persists the session state
// it established (the resolved, validated target). It shares the exact stage
// implementation used by Run so CLI and console have one pipeline.
func (r *Runner) RunDiscover(ctx context.Context, env *core.Env) error {
	return r.runUntil(ctx, env, StageDiscover)
}

// RunUntil runs the pipeline stages up to and including stopAfter, stopping
// before any later stage executes. An unknown stage is rejected.
func (r *Runner) RunUntil(ctx context.Context, env *core.Env, stopAfter string) error {
	known := false
	for _, name := range StageOrder {
		if name == stopAfter {
			known = true
			break
		}
	}
	if !known {
		return fmt.Errorf("unknown pipeline stage %q", stopAfter)
	}
	return r.runUntil(ctx, env, stopAfter)
}

func (r *Runner) runUntil(ctx context.Context, env *core.Env, stopAfter string) error {
	if env == nil || env.Session == nil {
		return errors.New("pipeline requires a session")
	}
	sess := env.Session
	if env.Events != nil {
		env.Events.Info(events.ScanStarted, map[string]any{
			"target": sess.TargetID, "profile": sess.Profile, "offline": env.Offline,
		})
	}
	sess.Start = time.Now().UTC()

	var fatal error
	for _, name := range StageOrder {
		if ctx.Err() != nil {
			fatal = ctx.Err()
			break
		}
		sess.Stages = append(sess.Stages, name)
		if env.Events != nil {
			env.Events.Info(events.StageStarted, map[string]any{"stage": name})
		}
		err := runStage(name, ctx, env)
		data := map[string]any{"stage": name}
		if err != nil {
			data["error"] = err.Error()
			sess.Errors = append(sess.Errors, name+": "+err.Error())
			if env.Events != nil {
				env.Events.Fail(events.StageCompleted, data)
			}
			// Collection-stage errors are degraded, the pipeline continues;
			// structural errors stop the run.
			if !strings.HasPrefix(name, StageCollect) {
				fatal = err
				break
			}
			continue
		}
		if env.Events != nil {
			env.Events.Info(events.StageCompleted, data)
		}
		if name == stopAfter {
			break
		}
	}

	relationships.Build(sess)
	sess.Finish()
	if env.Events != nil {
		env.Events.Info(events.ScanCompleted, map[string]any{
			"target": sess.TargetID, "status": statusString(fatal), "observations": len(sess.Observations),
			"findings": len(sess.Findings), "nodes": len(sess.Nodes), "edges": len(sess.Edges),
		})
	}
	return fatal
}

func statusString(err error) string {
	if err != nil {
		return "partial"
	}
	return "complete"
}

func runStage(name string, ctx context.Context, env *core.Env) error {
	switch name {
	case StageDiscover:
		return discover(ctx, env)
	case StageCollect:
		return collect(ctx, env)
	case StageNormalize:
		return normalize(ctx, env)
	case StageCorrelate:
		return correlate(ctx, env)
	case StageAnalyze:
		return analyze(ctx, env)
	case StageValidate:
		return validate(ctx, env)
	case StageReport:
		return report(ctx, env)
	default:
		return fmt.Errorf("unknown stage %q", name)
	}
}

// discover validates and normalizes the target, recording honest discovery
// hints. It never fabricates observations: none of the current sources expose
// a separate discovery surface, so discovery reduces to target normalization
// plus syntax validation.
func discover(ctx context.Context, env *core.Env) error {
	t := env.Target
	if t == nil {
		return errors.New("discover: no target")
	}
	if env.Session.Attributes == nil {
		env.Session.Attributes = map[string]string{}
	}
	name := strings.ToLower(strings.TrimSpace(t.TypedName()))
	value := strings.ToLower(strings.TrimSpace(t.Value))
	if t.Name != "" {
		value = strings.ToLower(strings.TrimSpace(t.Name))
	}
	switch t.Type {
	case models.TargetIP:
		if net.ParseIP(value) == nil {
			return fmt.Errorf("%w: %q", ErrInvalidIPTarget, value)
		}
	default:
		if name == "" {
			return fmt.Errorf("discover: empty target name")
		}
	}
	env.Session.Attributes["target.normalized"] = name
	if t.DisplayName() != "" {
		env.Session.Attributes["target.display"] = t.DisplayName()
	}
	if env.Log != nil {
		env.Log.Debugf("discover: normalized target %q (%s)", name, t.Type)
	}
	return nil
}

// collect runs the sources appropriate for the target type and stores their
// observations on the session. Per-source failures are appended to
// session.Errors, not returned, so a resolvable failure does not abort.
func collect(ctx context.Context, env *core.Env) error {
	t := env.Target
	sess := env.Session
	var observations []*models.Observation
	var errs []error

	switch t.Type {
	case models.TargetDomain, models.TargetInfrastructure:
		c := &domain.Collector{Registry: env.Registry, Config: env.Config, Log: env.Log}
		observations, errs = c.Collect(ctx, t, env.Offline)
	case models.TargetUsername:
		observations, errs = env.Registry.RunMode(ctx, env.Config, t, []string{"github", "simulation"}, env.Offline)
	case models.TargetOrganization:
		observations, errs = env.Registry.RunMode(ctx, env.Config, t, []string{"github", "simulation"}, env.Offline)
	case models.TargetIP:
		observations, errs = env.Registry.RunMode(ctx, env.Config, t, []string{"simulation"}, env.Offline)
	default:
		return fmt.Errorf("collect: unsupported target type %q", t.Type)
	}

	for _, obs := range observations {
		sess.AddObservation(obs)
	}
	for _, e := range errs {
		sess.Errors = append(sess.Errors, e.Error())
		if env.Log != nil {
			env.Log.Warnf("collect: %v", e)
		}
	}
	if env.Log != nil {
		env.Log.Infof("collect: %d observations (%d source(s) failed)", len(observations), len(errs))
	}
	return nil
}

// normalize types the collected observations into entities, edges and
// evidence using the observation vocabulary.
func normalize(ctx context.Context, env *core.Env) error {
	n := normalization.New(env.Session, env.Events)
	n.Normalize(ctx, env.Session.Observations)
	return nil
}

// correlate derives claims from the normalized entities.
func correlate(ctx context.Context, env *core.Env) error {
	correlation.New(env.Events).Run(env.Session)
	return nil
}

// analyze evaluates the builtin rules into findings.
func analyze(ctx context.Context, env *core.Env) error {
	sess := env.Session
	eng := rules.NewEngine().AddMany(builtin.All())
	findings := eng.Eval(rules.NewContext(sess), sess.TargetID, sess.ID)
	for _, f := range findings {
		sess.AddFinding(f)
		if env.Events != nil {
			env.Events.Info(events.FindingDiscovered, map[string]any{
				"rule_id": f.RuleID, "title": f.Title, "severity": f.Severity, "confidence": f.Confidence,
			})
		}
	}
	if env.Events != nil {
		env.Events.Info(events.AnalysisCompleted, map[string]any{
			"findings": len(sess.Findings), "claims": len(sess.Claims),
		})
	}
	return nil
}

// validate computes the target risk and verifies findings carry evidence.
// Findings without evidence are flagged rather than dropped, so the report
// stays honest about what is confirmed vs asserted.
func validate(ctx context.Context, env *core.Env) error {
	sess := env.Session
	assessor := &risk.Assessor{}
	score, level := assessor.Assess(ctx, sess.Findings)
	sess.RiskScore, sess.RiskLevel = score, level
	unverified := 0
	for _, f := range sess.Findings {
		if f != nil && len(f.Evidence) == 0 {
			unverified++
		}
	}
	if sess.Attributes == nil {
		sess.Attributes = map[string]string{}
	}
	if unverified > 0 {
		sess.Attributes["findings.unverified"] = formatInt(unverified)
	} else {
		delete(sess.Attributes, "findings.unverified")
	}
	if env.Events != nil {
		env.Events.Info(events.RiskCalculated, map[string]any{
			"score": score, "level": level, "unverified_findings": unverified,
		})
	}
	if env.Log != nil {
		env.Log.Infof("validate: risk %s (%d/100), %d unverified finding(s)", level, score, unverified)
	}
	return nil
}

// report writes the session to the report directory in every configured
// format. When no directory is configured the report is emitted to the event
// stream only (the CLI is responsible for stdout rendering).
func report(ctx context.Context, env *core.Env) error {
	sess := env.Session
	dir := sess.OutputDir
	formats := configuredFormats(env)
	if dir == "" {
		if env.Events != nil {
			for _, f := range formats {
				_, _ = reporting.Render(sess, f)
			}
			env.Events.Info(events.ReportGenerated, map[string]any{"dir": "stdout", "formats": joinStrings(formats)})
		}
		if env.Log != nil {
			env.Log.Infof("report: emitted %d format(s) to stdout", len(formats))
		}
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("report: %w", err)
	}
	written := []string{}
	for _, f := range formats {
		name := "report." + string(f)
		content, err := reporting.Render(sess, f)
		if err != nil {
			return fmt.Errorf("report %s: %w", f, err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return fmt.Errorf("report %s: %w", f, err)
		}
		written = append(written, p)
	}
	if env.Events != nil {
		env.Events.Info(events.ReportGenerated, map[string]any{"dir": dir, "formats": joinStrings(formats), "files": written})
	}
	if env.Log != nil {
		env.Log.Infof("report: wrote %d report file(s) to %s", len(written), dir)
	}
	return nil
}

func configuredFormats(env *core.Env) []reporting.Format {
	raw := env.Config.GetString("report.format")
	if raw == "" {
		return []reporting.Format{reporting.FormatTerminal, reporting.FormatJSON, reporting.FormatMarkdown}
	}
	var out []reporting.Format
	seen := map[reporting.Format]bool{}
	for _, part := range strings.Split(raw, ",") {
		f, err := reporting.ParseFormat(strings.TrimSpace(part))
		if err == nil && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return []reporting.Format{reporting.FormatTerminal}
	}
	return out
}

func joinStrings(list []reporting.Format) []string {
	out := make([]string, 0, len(list))
	for _, f := range list {
		out = append(out, string(f))
	}
	return out
}

func formatInt(v int) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
