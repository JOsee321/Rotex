package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/JOsee321/Rotex/internal/blast"
	"github.com/JOsee321/Rotex/internal/lockfile"
	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/output"
	"github.com/spf13/cobra"
)

const maxAdvisoryFileBytes = 10 << 20 // 10 MiB

type blastOptions struct {
	org             string
	repo            string
	pkgs            []string
	advisory        string
	since           time.Duration
	format          string
	withAWS         bool
	includeArchived bool
	concurrency     int
	apiURL          string
}

func newBlastCommand(deps Dependencies, noColor *bool) *cobra.Command {
	opts := &blastOptions{
		since:       72 * time.Hour,
		format:      string(output.FormatTable),
		concurrency: 5,
	}

	cmd := &cobra.Command{
		Use:   "blast",
		Short: "Map incident blast radius from a compromised package or advisory",
		Long: "Scan repository lockfiles and recent GitHub Actions workflow runs to identify " +
			"which secrets were exposed to a compromised dependency and prioritize rotation order.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBlast(cmd, deps, opts, noColor)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.org, "org", "", "GitHub organization to inspect")
	flags.StringVar(&opts.repo, "repo", "", "Single GitHub repository to inspect (owner/name)")
	flags.StringSliceVar(&opts.pkgs, "pkg", nil, "Compromised package spec (e.g. pkg@1.2.3 or pkg)")
	flags.StringVar(&opts.advisory, "advisory", "", "Path to an OSV or JSON advisory file")
	flags.DurationVar(&opts.since, "since", opts.since, "Incident lookback window for workflow runs (e.g. 72h)")
	flags.StringVar(&opts.format, "format", opts.format, "Output format (table|json|markdown)")
	flags.BoolVar(&opts.withAWS, "with-aws", false, "Correlate blast radius with read-only AWS IAM metadata")
	flags.BoolVar(&opts.includeArchived, "include-archived", false, "Include archived repositories")
	flags.IntVar(&opts.concurrency, "concurrency", opts.concurrency, "Maximum concurrent repository workers (1-16)")
	flags.StringVar(&opts.apiURL, "api-url", "", "Override GitHub REST API base URL (or set GITHUB_API_URL)")

	return cmd
}

func runBlast(cmd *cobra.Command, deps Dependencies, opts *blastOptions, noColor *bool) error {
	format, err := output.ParseFormat(opts.format)
	if err != nil {
		return err
	}

	var specs []lockfile.PackageSpec
	for _, rawPkg := range opts.pkgs {
		spec, specErr := lockfile.ParsePackageSpec(rawPkg)
		if specErr != nil {
			return specErr
		}
		specs = append(specs, spec)
	}
	if strings.TrimSpace(opts.advisory) != "" {
		rawAdv, readErr := readBoundedFile(opts.advisory, maxAdvisoryFileBytes)
		if readErr != nil {
			return fmt.Errorf("read advisory file %s: %w", opts.advisory, readErr)
		}
		advSpecs, parseErr := lockfile.ParseAdvisoryJSON(rawAdv)
		if parseErr != nil {
			return parseErr
		}
		specs = append(specs, advSpecs...)
	}
	if len(specs) == 0 {
		return errors.New("specify at least one --pkg or --advisory file")
	}

	token := resolveGitHubToken(deps.LookupEnv)

	apiURL := strings.TrimSpace(opts.apiURL)
	if apiURL == "" {
		apiURL = strings.TrimSpace(deps.LookupEnv("GITHUB_API_URL"))
	}

	ghClient := deps.GitHubClientFactory(token, apiURL)
	blastOpts := []blast.Option{
		blast.WithConcurrency(opts.concurrency),
		blast.WithAllowUnauthenticated(token.IsEmpty()),
	}
	if opts.withAWS {
		insp, awsErr := deps.AWSInspectorFactory(cmd.Context())
		if awsErr != nil {
			return sanitizeCLIError(awsErr, deps.LookupEnv, token.Expose())
		}
		blastOpts = append(blastOpts, blast.WithAWSInspector(insp))
	}

	svc := blast.NewService(ghClient, blastOpts...)
	report, err := svc.Analyze(cmd.Context(), blast.Request{
		Target: model.ScanTarget{
			Org:             strings.TrimSpace(opts.org),
			Repo:            strings.TrimSpace(opts.repo),
			IncludeArchived: opts.includeArchived,
		},
		Packages: specs,
		Since:    opts.since,
	})
	if err != nil {
		return sanitizeCLIError(err, deps.LookupEnv, token.Expose())
	}

	disableColor := (noColor != nil && *noColor) || deps.LookupEnv("NO_COLOR") != ""
	return output.RenderBlast(cmd.OutOrStdout(), report, output.Options{
		Format:  format,
		NoColor: disableColor,
	})
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file size exceeds %d byte limit", limit)
	}
	return data, nil
}
