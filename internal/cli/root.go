package cli

import (
	"github.com/spf13/cobra"
)

// NewRootCommand constructs the top-level rotex CLI command tree.
func NewRootCommand() *cobra.Command {
	var noColor bool

	cmd := &cobra.Command{
		Use:   "rotex",
		Short: "Map GitHub Actions secret blast radius and rotate credentials safely in-place",
		Long: "Rotex is a local-first, zero-knowledge security CLI that maps GitHub Actions " +
			"secret exposure across repositories and orchestrates safe, in-place credential rotation.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored terminal output")

	cmd.AddCommand(
		newVersionCommand(),
		newScanCommand(),
	)

	return cmd
}
