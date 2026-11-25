package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/JOsee321/Rotex/internal/aws"
	"github.com/JOsee321/Rotex/internal/github"
	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/output"
	"github.com/JOsee321/Rotex/internal/rotate"
	"github.com/JOsee321/Rotex/internal/security"
	"github.com/spf13/cobra"
)

type rotateOptions struct {
	iamUser         string
	oldKeyID        string
	repos           []string
	envs            []string
	org             string
	secrets         []string
	plan            bool
	dryRun          bool
	apply           bool
	immediateDelete bool
	stateDir        string
	format          string
	apiURL          string
	iamEndpoint     string
	stsEndpoint     string
	verifyTimeout   time.Duration
	verifyBackoff   time.Duration
}

func newRotateCommand(deps Dependencies, noColor *bool) *cobra.Command {
	opts := &rotateOptions{
		format:        string(output.FormatTable),
		stateDir:      ".rotex/state",
		verifyTimeout: 30 * time.Second,
		verifyBackoff: 1 * time.Second,
	}

	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Safely rotate AWS IAM credentials in-place across GitHub Actions secrets",
		Long: "Execute a safe dual-key rotation workflow: preflight check, mint new AWS IAM key, " +
			"encrypt locally with libsodium sealed box, inject into GitHub Secrets, verify via STS, " +
			"and deactivate the old key with automatic rollback on failure.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRotate(cmd, deps, opts, noColor)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.iamUser, "iam-user", "", "AWS IAM user name whose access key will be rotated")
	flags.StringVar(&opts.oldKeyID, "old-key-id", "", "Existing AWS IAM access key ID to deactivate after verification")
	flags.StringSliceVar(&opts.repos, "repo", nil, "Target GitHub repository (owner/name, repeatable)")
	flags.StringSliceVar(&opts.envs, "env", nil, "Target GitHub environment (owner/name:env, repeatable)")
	flags.StringVar(&opts.org, "org", "", "Target GitHub organization secret scope")
	flags.StringSliceVar(&opts.secrets, "secret", nil, "GitHub secret names to update (default AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY)")
	flags.BoolVar(&opts.plan, "plan", false, "Preview deterministic execution plan without mutating APIs")
	flags.BoolVar(&opts.dryRun, "dry-run", false, "Alias for --plan (no mutations)")
	flags.BoolVar(&opts.apply, "apply", false, "Apply the rotation state machine")
	flags.BoolVar(&opts.immediateDelete, "immediate-delete", false, "Delete the old IAM key immediately after verification")
	flags.StringVar(&opts.stateDir, "state-dir", opts.stateDir, "Directory for local rotation state journals")
	flags.StringVar(&opts.format, "format", opts.format, "Output format (table|json|markdown)")
	flags.StringVar(&opts.apiURL, "api-url", "", "Override GitHub REST API base URL (or set GITHUB_API_URL)")
	flags.StringVar(&opts.iamEndpoint, "aws-iam-endpoint", "", "Override AWS IAM endpoint URL")
	flags.StringVar(&opts.stsEndpoint, "aws-sts-endpoint", "", "Override AWS STS endpoint URL")
	flags.DurationVar(&opts.verifyTimeout, "verify-timeout", opts.verifyTimeout, "Maximum STS eventual-consistency verification wait")
	flags.DurationVar(&opts.verifyBackoff, "verify-backoff", opts.verifyBackoff, "Initial retry backoff for STS verification")

	return cmd
}

type runIDOptions struct {
	runID       string
	stateDir    string
	format      string
	iamEndpoint string
	stsEndpoint string
}

func newRollbackCommand(deps Dependencies, noColor *bool) *cobra.Command {
	opts := &runIDOptions{
		stateDir: ".rotex/state",
		format:   string(output.FormatTable),
	}
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Roll back a recorded rotation run using its local state journal",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runLifecycleAction(cmd, deps, opts, noColor, true)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.runID, "run-id", "", "Rotation run ID from .rotex/state/<run-id>.json")
	flags.StringVar(&opts.stateDir, "state-dir", opts.stateDir, "Directory for local rotation state journals")
	flags.StringVar(&opts.format, "format", opts.format, "Output format (table|json|markdown)")
	flags.StringVar(&opts.iamEndpoint, "aws-iam-endpoint", "", "Override AWS IAM endpoint URL")
	flags.StringVar(&opts.stsEndpoint, "aws-sts-endpoint", "", "Override AWS STS endpoint URL")
	return cmd
}

func newCleanupCommand(deps Dependencies, noColor *bool) *cobra.Command {
	opts := &runIDOptions{
		stateDir: ".rotex/state",
		format:   string(output.FormatTable),
	}
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Permanently delete the deactivated old key for a completed rotation run",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runLifecycleAction(cmd, deps, opts, noColor, false)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.runID, "run-id", "", "Rotation run ID from .rotex/state/<run-id>.json")
	flags.StringVar(&opts.stateDir, "state-dir", opts.stateDir, "Directory for local rotation state journals")
	flags.StringVar(&opts.format, "format", opts.format, "Output format (table|json|markdown)")
	flags.StringVar(&opts.iamEndpoint, "aws-iam-endpoint", "", "Override AWS IAM endpoint URL")
	flags.StringVar(&opts.stsEndpoint, "aws-sts-endpoint", "", "Override AWS STS endpoint URL")
	return cmd
}

func runRotate(cmd *cobra.Command, deps Dependencies, opts *rotateOptions, noColor *bool) error {
	if opts.apply && (opts.plan || opts.dryRun) {
		return errors.New("cannot combine --apply with --plan or --dry-run")
	}

	format, err := output.ParseFormat(opts.format)
	if err != nil {
		return err
	}

	storeTargets, err := buildStoreTargets(opts.org, opts.repos, opts.envs)
	if err != nil {
		return err
	}

	token := resolveGitHubToken(deps.LookupEnv)
	if token.IsEmpty() {
		return errors.New("GITHUB_TOKEN (or GH_TOKEN) environment variable is required")
	}

	apiURL := firstNonEmpty(opts.apiURL, deps.LookupEnv("GITHUB_API_URL"))
	iamEP := firstNonEmpty(opts.iamEndpoint, deps.LookupEnv("ROTEX_AWS_IAM_ENDPOINT"), deps.LookupEnv("AWS_ENDPOINT_URL_IAM"))
	stsEP := firstNonEmpty(opts.stsEndpoint, deps.LookupEnv("ROTEX_AWS_STS_ENDPOINT"), deps.LookupEnv("AWS_ENDPOINT_URL_STS"))

	provider, err := deps.AWSRotatorFactory(cmd.Context(), iamEP, stsEP, opts.verifyTimeout, opts.verifyBackoff)
	if err != nil {
		return err
	}
	store := deps.SecretStoreFactory(token, apiURL)

	engine := rotate.NewEngine(provider, store, rotate.WithJournal(rotate.NewJournal(opts.stateDir)))
	req := rotate.Request{
		Target: rotate.KeyTarget{
			IAMUser:  strings.TrimSpace(opts.iamUser),
			OldKeyID: strings.TrimSpace(opts.oldKeyID),
		},
		StoreTargets:    storeTargets,
		SecretNames:     opts.secrets,
		ImmediateDelete: opts.immediateDelete,
	}

	disableColor := (noColor != nil && *noColor) || deps.LookupEnv("NO_COLOR") != ""
	outOpts := output.Options{Format: format, NoColor: disableColor}

	if !opts.apply {
		plan, planErr := engine.Plan(cmd.Context(), req)
		if planErr != nil {
			return sanitizeCLIError(planErr, deps.LookupEnv, token.Expose())
		}
		return output.RenderRotationPlan(cmd.OutOrStdout(), plan, outOpts)
	}

	state, applyErr := engine.Apply(cmd.Context(), req)
	if state != nil {
		sanitizeRunStateSecrets(state, deps.LookupEnv, token.Expose())
		_ = output.RenderRunState(cmd.OutOrStdout(), state, outOpts)
	}
	if applyErr != nil {
		return sanitizeCLIError(applyErr, deps.LookupEnv, token.Expose())
	}
	return nil
}

func runLifecycleAction(cmd *cobra.Command, deps Dependencies, opts *runIDOptions, noColor *bool, isRollback bool) error {
	if strings.TrimSpace(opts.runID) == "" {
		return errors.New("--run-id is required")
	}
	format, err := output.ParseFormat(opts.format)
	if err != nil {
		return err
	}

	iamEP := firstNonEmpty(opts.iamEndpoint, deps.LookupEnv("ROTEX_AWS_IAM_ENDPOINT"), deps.LookupEnv("AWS_ENDPOINT_URL_IAM"))
	stsEP := firstNonEmpty(opts.stsEndpoint, deps.LookupEnv("ROTEX_AWS_STS_ENDPOINT"), deps.LookupEnv("AWS_ENDPOINT_URL_STS"))

	provider, err := deps.AWSRotatorFactory(cmd.Context(), iamEP, stsEP, 30*time.Second, time.Second)
	if err != nil {
		return sanitizeCLIError(err, deps.LookupEnv)
	}

	engine := rotate.NewEngine(provider, nil, rotate.WithJournal(rotate.NewJournal(opts.stateDir)))
	var state *rotate.RunState
	if isRollback {
		state, err = engine.Rollback(cmd.Context(), opts.runID)
	} else {
		state, err = engine.Cleanup(cmd.Context(), opts.runID)
	}
	if err != nil {
		return sanitizeCLIError(err, deps.LookupEnv)
	}

	sanitizeRunStateSecrets(state, deps.LookupEnv)
	disableColor := (noColor != nil && *noColor) || deps.LookupEnv("NO_COLOR") != ""
	return output.RenderRunState(cmd.OutOrStdout(), state, output.Options{Format: format, NoColor: disableColor})
}

func buildStoreTargets(org string, repos, envs []string) ([]rotate.StoreScope, error) {
	var targets []rotate.StoreScope
	if trimmedOrg := strings.TrimSpace(org); trimmedOrg != "" {
		if trimmedOrg == "." || trimmedOrg == ".." || strings.ContainsAny(trimmedOrg, `/\`) {
			return nil, fmt.Errorf("invalid --org %q", org)
		}
		targets = append(targets, rotate.StoreScope{Scope: model.ScopeOrg, Org: trimmedOrg})
	}
	for _, r := range repos {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if err := validateRepoFlag(r); err != nil {
			return nil, fmt.Errorf("invalid --repo %q: %w", r, err)
		}
		targets = append(targets, rotate.StoreScope{Scope: model.ScopeRepo, Repo: r})
	}
	for _, e := range envs {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		repoPart, envName, ok := strings.Cut(e, ":")
		if !ok || strings.TrimSpace(envName) == "" {
			return nil, fmt.Errorf("invalid --env %q: expected owner/name:environment", e)
		}
		if err := validateRepoFlag(repoPart); err != nil {
			return nil, fmt.Errorf("invalid --env %q: %w", e, err)
		}
		envTrimmed := strings.TrimSpace(envName)
		if envTrimmed == "." || envTrimmed == ".." || strings.ContainsAny(envTrimmed, `/\`) {
			return nil, fmt.Errorf("invalid --env %q: invalid environment name", e)
		}
		targets = append(targets, rotate.StoreScope{Scope: model.ScopeEnvironment, Repo: repoPart, Environment: envTrimmed})
	}
	return targets, nil
}

func validateRepoFlag(repo string) error {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return errors.New("expected owner/name")
	}
	if owner == "." || owner == ".." || name == "." || name == ".." || strings.ContainsAny(repo, `\ `) {
		return errors.New("invalid repository path segment")
	}
	return nil
}

func collectEnvSecrets(lookup func(string) string, extra ...string) []string {
	secrets := append([]string{}, extra...)
	if lookup != nil {
		for _, k := range []string{"GITHUB_TOKEN", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
			if v := strings.TrimSpace(lookup(k)); v != "" {
				secrets = append(secrets, v)
			}
		}
	}
	return secrets
}

func sanitizeCLIError(err error, lookup func(string) string, extra ...string) error {
	return security.SanitizeError(err, collectEnvSecrets(lookup, extra...)...)
}

func sanitizeRunStateSecrets(state *rotate.RunState, lookup func(string) string, extra ...string) {
	if state == nil {
		return
	}
	secrets := collectEnvSecrets(lookup, extra...)
	state.Error = security.SanitizeString(state.Error, secrets...)
	for i := range state.Targets {
		state.Targets[i].Error = security.SanitizeString(state.Targets[i].Error, secrets...)
	}
}

func defaultRotatorFactory(ctx context.Context, iamEP, stsEP string, verifyTimeout, verifyBackoff time.Duration) (rotate.CredentialProvider, error) {
	rotator, err := aws.NewDefaultRotator(ctx, iamEP, stsEP)
	if err != nil {
		return nil, err
	}
	aws.WithVerifyBackoff(verifyTimeout, verifyBackoff)(rotator)
	return rotator, nil
}

func defaultSecretStoreFactory(token security.SensitiveString, apiURL string) rotate.SecretStore {
	var opts []github.Option
	if apiURL != "" {
		opts = append(opts, github.WithBaseURL(apiURL))
	}
	return github.NewSecretStore(github.NewRESTClient(token, opts...))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
