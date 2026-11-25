package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

type scanOptions struct {
	org     string
	repo    string
	format  string
	withAWS bool
}

func newScanCommand() *cobra.Command {
	opts := &scanOptions{
		format: "table",
	}

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Discover GitHub Actions secrets and map workflow exposure (read-only)",
		Long: "Inspect GitHub Actions secret metadata and workflow YAML definitions across an " +
			"organization or repository to map secret usage, age, and risky workflow triggers. " +
			"This command is strictly read-only and never accesses raw secret values.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return errors.New("scan command is not implemented yet")
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.org, "org", "", "GitHub organization to scan")
	flags.StringVar(&opts.repo, "repo", "", "Single GitHub repository to scan (owner/name)")
	flags.StringVar(&opts.format, "format", opts.format, "Output format (table|json|markdown)")
	flags.BoolVar(&opts.withAWS, "with-aws", false, "Correlate findings with read-only AWS IAM metadata")

	return cmd
}
