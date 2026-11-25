package cli

import (
	"strings"

	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/output"
	"github.com/JOsee321/Rotex/internal/scanner"
	"github.com/JOsee321/Rotex/internal/security"
	"github.com/spf13/cobra"
)

type scanOptions struct {
	org             string
	repo            string
	format          string
	withAWS         bool
	includeArchived bool
	concurrency     int
	apiURL          string
}

func newScanCommand(deps Dependencies, noColor *bool) *cobra.Command {
	opts := &scanOptions{
		format:      string(output.FormatTable),
		concurrency: 5,
	}

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Discover GitHub Actions secrets and map workflow exposure (read-only)",
		Long: "Inspect GitHub Actions secret metadata and workflow YAML definitions across an " +
			"organization or repository to map secret usage, age, and risky workflow triggers. " +
			"This command is strictly read-only and never accesses raw secret values.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd, deps, opts, noColor)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.org, "org", "", "GitHub organization to scan")
	flags.StringVar(&opts.repo, "repo", "", "Single GitHub repository to scan (owner/name)")
	flags.StringVar(&opts.format, "format", opts.format, "Output format (table|json|markdown)")
	flags.BoolVar(&opts.withAWS, "with-aws", false, "Correlate findings with read-only AWS IAM metadata")
	flags.BoolVar(&opts.includeArchived, "include-archived", false, "Include archived repositories in the scan")
	flags.IntVar(&opts.concurrency, "concurrency", opts.concurrency, "Maximum concurrent repository workers (1-16)")
	flags.StringVar(&opts.apiURL, "api-url", "", "Override GitHub REST API base URL (or set GITHUB_API_URL)")

	return cmd
}

func runScan(cmd *cobra.Command, deps Dependencies, opts *scanOptions, noColor *bool) error {
	format, err := output.ParseFormat(opts.format)
	if err != nil {
		return err
	}

	token := resolveGitHubToken(deps.LookupEnv)

	apiURL := strings.TrimSpace(opts.apiURL)
	if apiURL == "" {
		apiURL = strings.TrimSpace(deps.LookupEnv("GITHUB_API_URL"))
	}

	ghClient := deps.GitHubClientFactory(token, apiURL)
	scannerOpts := []scanner.Option{
		scanner.WithConcurrency(opts.concurrency),
		scanner.WithAllowUnauthenticated(token.IsEmpty()),
	}

	if opts.withAWS {
		insp, awsErr := deps.AWSInspectorFactory(cmd.Context())
		if awsErr != nil {
			return sanitizeCLIError(awsErr, deps.LookupEnv, token.Expose())
		}
		scannerOpts = append(scannerOpts, scanner.WithAWSInspector(insp))
	}

	svc := scanner.NewService(ghClient, scannerOpts...)

	target := model.ScanTarget{
		Org:             strings.TrimSpace(opts.org),
		Repo:            strings.TrimSpace(opts.repo),
		IncludeArchived: opts.includeArchived,
	}

	report, err := svc.Scan(cmd.Context(), target)
	if err != nil {
		return sanitizeCLIError(err, deps.LookupEnv, token.Expose())
	}

	disableColor := (noColor != nil && *noColor) || deps.LookupEnv("NO_COLOR") != ""
	return output.Render(cmd.OutOrStdout(), report, output.Options{
		Format:  format,
		NoColor: disableColor,
	})
}

func resolveGitHubToken(lookup func(string) string) security.SensitiveString {
	if tok := strings.TrimSpace(lookup("GITHUB_TOKEN")); tok != "" {
		return security.NewSensitiveString(tok)
	}
	if tok := strings.TrimSpace(lookup("GH_TOKEN")); tok != "" {
		return security.NewSensitiveString(tok)
	}
	return security.SensitiveString{}
}
