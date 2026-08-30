package cli

import (
	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

func newTargetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "target",
		Aliases: []string{"tgt"},
		Short:   "Manage collection targets",
	}
	cmd.AddCommand(newTargetSetCmd())
	cmd.AddCommand(newTargetListCmd())
	cmd.AddCommand(newTargetShowCmd())
	return cmd
}

func newTargetSetCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "set [value]",
		Short: "Select and authorize the current collection target",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := targetFlagsFrom(cmd)
			if opts.value == "" && len(args) == 1 {
				opts.value = args[0]
			}
			t, err := app.establishTarget(cmd, opts)
			if err != nil {
				return err
			}
			if name != "" {
				t.Name = name
			}
			if err := app.targets.Set(t); err != nil {
				return err
			}
			app.emitf("current target: %s (%s) [%s]", t.DisplayName(), t.Type, string(t.Auth.Method))
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "friendly target name")
	registerTargetFlags(cmd.Flags())
	return cmd
}

func newTargetListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List known targets",
		Run: func(_ *cobra.Command, _ []string) {
			ts := app.targets.List()
			if len(ts) == 0 {
				app.emitf("no targets; run 'nzinga target set'")
				return
			}
			var rows [][]string
			for _, t := range ts {
				rows = append(rows, []string{t.TypedName(), string(t.Type), authState(t)})
			}
			app.printer.PrintTable([]string{"target", "type", "authorized"}, rows)
		},
	}
}

func newTargetShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the current target",
		Run: func(_ *cobra.Command, _ []string) {
			t := app.targets.Current()
			if t == nil {
				app.emitf("no current target")
				return
			}
			app.printer.Print(t)
		},
	}
}

func authState(t *models.Target) string {
	if t.Authorized() {
		return "yes (" + t.Auth.Method + ")"
	}
	return "no"
}
