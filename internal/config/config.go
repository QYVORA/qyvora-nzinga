// Package config loads and exposes assessment configuration. Configuration
// comes from a YAML file, the QYVORA_NZINGA_* environment namespace, and
// safe defaults, in that order of precedence. Invalid configured values are
// rejected rather than silently accepted.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const appName = "qyvora-nzinga"

// DefaultTimeout for collection operations when none is configured.
const DefaultTimeout = 15 * time.Second

// Profile names. Nzinga's profiles select the depth/width of a collection
// run; each is a clearly defined scope, never "do less because we got bored".
const (
	ProfileQuick    = "quick"
	ProfileStandard = "standard"
	ProfileDeep     = "deep"
)

// Profiles lists every supported profile in documentation order.
var Profiles = []string{
	ProfileQuick, ProfileStandard, ProfileDeep,
}

// IsValidProfile reports whether name is a known profile.
func IsValidProfile(name string) bool {
	for _, p := range Profiles {
		if p == name {
			return true
		}
	}
	return false
}

// Load builds a viper configuration from a config file (when given), the
// QYVORA_NZINGA_* environment namespace, and defaults. A missing config file
// is not an error; a malformed one is.
func Load(cfgFile string) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")

	for _, dir := range configSearchDirs(cfgFile) {
		v.AddConfigPath(dir)
	}

	v.SetEnvPrefix("QYVORA_NZINGA")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	v.SetDefault("profile", ProfileStandard)
	v.SetDefault("output", "terminal")
	v.SetDefault("verbose", false)
	v.SetDefault("quiet", false)
	v.SetDefault("json", false)
	v.SetDefault("authorized", false)
	v.SetDefault("report.dir", "reports")
	v.SetDefault("report.format", "terminal")
	v.SetDefault("log.level", "info")
	v.SetDefault("session.dir", "")
	v.SetDefault("target.state", defaultTargetState())

	// Collection layer defaults (shared hardened client).
	v.SetDefault("collection.timeout_seconds", 15)
	v.SetDefault("collection.source_concurrency", 1)
	v.SetDefault("collection.user_agent", defaultUserAgent)
	v.SetDefault("collection.max_response_bytes", 1048576)
	v.SetDefault("collection.redirects", false)
	v.SetDefault("collection.http_proxy", "")
	v.SetDefault("collection.max_retries", 2)
	v.SetDefault("collection.rate_limit_per_second", 2)

	// Per-source enablement.
	v.SetDefault("sources.crt_sh.enabled", true)
	v.SetDefault("sources.dns.enabled", true)
	v.SetDefault("sources.whois.enabled", true)
	v.SetDefault("sources.whois.port", 43)
	v.SetDefault("sources.github.enabled", true)
	v.SetDefault("sources.github.token", "")
	v.SetDefault("sources.abuseipdb.enabled", true)
	v.SetDefault("sources.abuseipdb.token", "")
	v.SetDefault("sources.simulation.enabled", true)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}
	return v, nil
}

// Profile returns the configured profile name, validated against the known
// set. An invalid configured profile is an error so a typo cannot silently
// change what an assessment does.
func Profile(v *viper.Viper) (string, error) {
	p := v.GetString("profile")
	if !IsValidProfile(p) {
		return "", fmt.Errorf("unknown profile %q (valid: %s)", p, strings.Join(Profiles, ", "))
	}
	return p, nil
}

// Timeout returns the configured collection timeout.
func Timeout(v *viper.Viper) time.Duration {
	secs := v.GetInt("collection.timeout_seconds")
	if secs <= 0 {
		return DefaultTimeout
	}
	return time.Duration(secs) * time.Second
}

// UserAgent returns the configured HTTP user agent.
func UserAgent(v *viper.Viper) string {
	ua := v.GetString("collection.user_agent")
	if ua == "" {
		return defaultUserAgent
	}
	return ua
}

// MaxResponseBytes returns the configured per-response body cap.
func MaxResponseBytes(v *viper.Viper) int64 {
	n := v.GetInt64("collection.max_response_bytes")
	if n <= 0 {
		return 1 << 20
	}
	return n
}

// FollowRedirects reports whether the shared client may follow redirects.
func FollowRedirects(v *viper.Viper) bool { return v.GetBool("collection.redirects") }

const defaultUserAgent = "QYVORA-NZINGA/0.1 (authorized osint; contact owner before use)"

// defaultTargetState returns the default on-disk location for the target
// manager state. Returning "" keeps targets in-memory only (e.g. when the
// home directory cannot be resolved).
func defaultTargetState() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "qyvora", "nzinga", "targets.json")
}

func configSearchDirs(cfgFile string) []string {
	dirs := []string{"."}

	if cfgFile != "" {
		if info, err := os.Stat(cfgFile); err == nil && info.IsDir() {
			dirs = append(dirs, cfgFile)
		} else {
			dirs = append(dirs, filepath.Dir(cfgFile))
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "."+appName))
		dirs = append(dirs, filepath.Join(home, ".config", "qyvora", "nzinga"))
	}

	dirs = append(dirs, filepath.Join("/etc", appName))
	return dirs
}
