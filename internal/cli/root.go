package cli

import (
	"context"
	"os"

	"github.com/JOsee321/Rotex/internal/aws"
	"github.com/JOsee321/Rotex/internal/github"
	"github.com/JOsee321/Rotex/internal/security"
	"github.com/spf13/cobra"
)

// Dependencies supplies external clients and environment readers for CLI commands.
type Dependencies struct {
	GitHubClientFactory func(token security.SensitiveString, apiURL string) github.Client
	AWSInspectorFactory func(ctx context.Context) (aws.Inspector, error)
	LookupEnv           func(key string) string
}

func defaultDependencies() Dependencies {
	return Dependencies{
		GitHubClientFactory: func(token security.SensitiveString, apiURL string) github.Client {
			var opts []github.Option
			if apiURL != "" {
				opts = append(opts, github.WithBaseURL(apiURL))
			}
			return github.NewRESTClient(token, opts...)
		},
		AWSInspectorFactory: func(ctx context.Context) (aws.Inspector, error) {
			return aws.NewDefaultInspector(ctx)
		},
		LookupEnv: os.Getenv,
	}
}

// NewRootCommand constructs the top-level rotex CLI command tree with default dependencies.
func NewRootCommand() *cobra.Command {
	return NewRootCommandWithDeps(defaultDependencies())
}

// NewRootCommandWithDeps constructs the top-level rotex CLI command tree using custom dependencies.
func NewRootCommandWithDeps(deps Dependencies) *cobra.Command {
	if deps.LookupEnv == nil {
		deps.LookupEnv = os.Getenv
	}
	if deps.GitHubClientFactory == nil {
		deps.GitHubClientFactory = defaultDependencies().GitHubClientFactory
	}
	if deps.AWSInspectorFactory == nil {
		deps.AWSInspectorFactory = defaultDependencies().AWSInspectorFactory
	}

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
		newScanCommand(deps, &noColor),
		newBlastCommand(deps, &noColor),
	)

	return cmd
}
