package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

// registerTargetFlags adds the shared target flags to a flag set so the same
// flags work on assess/domain/organization/username/ip commands.
func registerTargetFlags(fs *pflag.FlagSet) {
	fs.String("target", "", "target value (e.g. example.com, alice, 203.0.113.10, Example Corp)")
	fs.String("type", "", "target type: domain, organization, username, ip, infrastructure")
	fs.String("profile", "", "collection profile: quick, standard, deep")
	fs.Bool("sim", false, "run against the built-in offline simulation dataset")
}

// targetFlags reads the target flags from a command.
func targetFlagsFrom(cmd *cobra.Command) targetOptions {
	return targetOptions{
		value:   flagString(cmd, "target"),
		typ:     flagString(cmd, "type"),
		profile: flagString(cmd, "profile"),
		sim:     flagBool(cmd, "sim"),
	}
}

// targetOptions collects the target description shared by the collection
// commands.
type targetOptions struct {
	value   string
	typ     string
	profile string
	sim     bool
}

func (o targetOptions) empty() bool {
	return o.value == "" && o.typ == "" && !o.sim
}

func (o targetOptions) targetType() models.TargetType {
	if o.typ == "" {
		return models.TargetDomain
	}
	switch models.TargetType(o.typ) {
	case models.TargetDomain, models.TargetOrganization, models.TargetUsername, models.TargetIP, models.TargetInfrastructure:
		return models.TargetType(o.typ)
	default:
		return models.TargetDomain
	}
}

func flagString(cmd *cobra.Command, name string) string {
	if cmd == nil || cmd.Flags() == nil {
		return ""
	}
	v, _ := cmd.Flags().GetString(name)
	return v
}

func flagBool(cmd *cobra.Command, name string) bool {
	if cmd == nil || cmd.Flags() == nil {
		return false
	}
	v, _ := cmd.Flags().GetBool(name)
	return v
}

func flagInt(cmd *cobra.Command, name string) int {
	if cmd == nil || cmd.Flags() == nil {
		return 0
	}
	v, _ := cmd.Flags().GetInt(name)
	return v
}
