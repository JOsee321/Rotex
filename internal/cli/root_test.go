package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/JOsee321/Rotex/internal/aws"
	"github.com/JOsee321/Rotex/internal/github"
	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/rotate"
	"github.com/JOsee321/Rotex/internal/security"
)

type stubAWSInspector struct {
	report *aws.AuditReport
}

func (s *stubAWSInspector) Inspect(_ context.Context, _ time.Duration) (*aws.AuditReport, error) {
	return s.report, nil
}

type stubGitHubClient struct {
	repo        github.Repository
	repoSecrets []model.SecretMetadata
	envs        []github.Environment
	envSecrets  map[string][]model.SecretMetadata
	workflows   []github.WorkflowFile
}

func (s *stubGitHubClient) ListOrgRepos(_ context.Context, _ string) ([]github.Repository, error) {
	return []github.Repository{s.repo}, nil
}

func (s *stubGitHubClient) GetRepo(_ context.Context, _, _ string) (github.Repository, error) {
	return s.repo, nil
}

func (s *stubGitHubClient) ListOrgSecrets(_ context.Context, _ string) ([]model.SecretMetadata, error) {
	return nil, nil
}

func (s *stubGitHubClient) ListRepoSecrets(_ context.Context, _, _ string) ([]model.SecretMetadata, error) {
	return s.repoSecrets, nil
}

func (s *stubGitHubClient) ListEnvironments(_ context.Context, _, _ string) ([]github.Environment, error) {
	return s.envs, nil
}

func (s *stubGitHubClient) ListEnvironmentSecrets(_ context.Context, _, _, env string) ([]model.SecretMetadata, error) {
	return s.envSecrets[env], nil
}

func (s *stubGitHubClient) ListWorkflowFiles(_ context.Context, _, _, _ string) ([]github.WorkflowFile, error) {
	return s.workflows, nil
}

func (s *stubGitHubClient) ListRepoLockfiles(_ context.Context, _, _, _ string) ([]github.RepoFile, error) {
	return nil, nil
}

func (s *stubGitHubClient) ListWorkflowRuns(_ context.Context, _, _ string, _ time.Time) ([]github.WorkflowRun, error) {
	return nil, nil
}

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	if !strings.Contains(out.String(), "rotex ") {
		t.Fatalf("unexpected version output: %q", out.String())
	}
}

func TestScanHelpCommand(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"scan", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan --help failed: %v", err)
	}

	output := out.String()
	for _, flag := range []string{"--org", "--repo", "--format", "--with-aws", "--include-archived", "--concurrency"} {
		if !strings.Contains(output, flag) {
			t.Fatalf("expected %s flag in scan help output, got:\n%s", flag, output)
		}
	}
}

func TestScanCommandExecutionJSONAndValidation(t *testing.T) {
	stub := &stubGitHubClient{
		repo: github.Repository{Owner: "octocat", Name: "hello", FullName: "octocat/hello", DefaultBranch: "main"},
		repoSecrets: []model.SecretMetadata{
			{
				Name:      "DEPLOY_TOKEN",
				Scope:     model.ScopeRepo,
				Owner:     "octocat",
				Repo:      "octocat/hello",
				UpdatedAt: time.Now().UTC().Add(-100 * 24 * time.Hour),
			},
		},
		workflows: []github.WorkflowFile{
			{
				Path:    ".github/workflows/ci.yml",
				Content: []byte("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n        env:\n          TOK: ${{ secrets.DEPLOY_TOKEN }}\n"),
			},
		},
	}

	deps := Dependencies{
		LookupEnv: func(key string) string {
			if key == "GITHUB_TOKEN" {
				return "ghp_mock_token"
			}
			return ""
		},
		GitHubClientFactory: func(_ security.SensitiveString, _ string) github.Client {
			return stub
		},
	}

	var out bytes.Buffer
	cmd := NewRootCommandWithDeps(deps)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"scan", "--repo", "octocat/hello", "--format", "json", "--no-color"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan command failed: %v", err)
	}

	if strings.Contains(out.String(), "ghp_mock_token") {
		t.Fatalf("output leaked token")
	}

	var report model.ScanReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON report: %v\n%s", err, out.String())
	}
	if report.Summary.UniqueSecrets != 1 || report.Exposures[0].SecretName != "DEPLOY_TOKEN" {
		t.Fatalf("unexpected report: %+v", report)
	}

	// Unauthenticated scan should degrade gracefully with a warning.
	var unauthOut bytes.Buffer
	noTokCmd := NewRootCommandWithDeps(Dependencies{
		LookupEnv:           func(string) string { return "" },
		GitHubClientFactory: func(_ security.SensitiveString, _ string) github.Client { return stub },
	})
	noTokCmd.SetOut(&unauthOut)
	noTokCmd.SetArgs([]string{"scan", "--repo", "octocat/hello", "--format", "json"})
	if err := noTokCmd.Execute(); err != nil {
		t.Fatalf("expected unauthenticated scan to succeed with warning, got: %v", err)
	}
	var unauthRep model.ScanReport
	if err := json.Unmarshal(unauthOut.Bytes(), &unauthRep); err != nil {
		t.Fatalf("invalid unauthenticated scan JSON: %v", err)
	}
	if len(unauthRep.Warnings) == 0 || unauthRep.Warnings[0].Code != "unauthenticated" {
		t.Fatalf("expected unauthenticated warning, got: %+v", unauthRep.Warnings)
	}

	// Write command (rotate) must still reject missing token.
	rotNoTok := NewRootCommandWithDeps(Dependencies{
		LookupEnv: func(string) string { return "" },
	})
	rotNoTok.SetArgs([]string{"rotate", "--iam-user", "ci", "--repo", "octocat/hello"})
	if err := rotNoTok.Execute(); err == nil || !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Fatalf("expected missing token error on rotate, got: %v", err)
	}
}

func TestScanCommandWithAWSFlag(t *testing.T) {
	stub := &stubGitHubClient{
		repo: github.Repository{Owner: "octocat", Name: "hello", FullName: "octocat/hello", DefaultBranch: "main"},
		repoSecrets: []model.SecretMetadata{
			{Name: "AWS_ACCESS_KEY_ID", Scope: model.ScopeRepo, Owner: "octocat", Repo: "octocat/hello", UpdatedAt: time.Now().UTC()},
		},
	}

	deps := Dependencies{
		LookupEnv: func(key string) string {
			if key == "GITHUB_TOKEN" {
				return "ghp_mock"
			}
			return ""
		},
		GitHubClientFactory: func(_ security.SensitiveString, _ string) github.Client { return stub },
		AWSInspectorFactory: func(_ context.Context) (aws.Inspector, error) {
			return &stubAWSInspector{
				report: &aws.AuditReport{
					Keys: []aws.AccessKeyAudit{
						{UserName: "ci-bot", AccessKeyID: "AKIA_TEST", Status: "Active", AgeDays: 120, Stale: true},
					},
				},
			}, nil
		},
	}

	var out bytes.Buffer
	cmd := NewRootCommandWithDeps(deps)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"scan", "--repo", "octocat/hello", "--with-aws", "--format", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan --with-aws failed: %v", err)
	}
	var report model.ScanReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(report.AWSKeys) != 1 || report.Exposures[0].AWS == nil {
		t.Fatalf("expected AWS key correlation in report: %+v", report)
	}
}

func TestBlastCommandExecution(t *testing.T) {
	stub := &stubGitHubClient{
		repo: github.Repository{Owner: "octocat", Name: "hello", FullName: "octocat/hello", DefaultBranch: "main"},
		repoSecrets: []model.SecretMetadata{
			{Name: "NPM_TOKEN", Scope: model.ScopeRepo, Owner: "octocat", Repo: "octocat/hello", UpdatedAt: time.Now().UTC()},
		},
		workflows: []github.WorkflowFile{
			{
				Path:    ".github/workflows/ci.yml",
				Content: []byte("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n"),
			},
		},
	}

	deps := Dependencies{
		LookupEnv: func(key string) string {
			if key == "GITHUB_TOKEN" {
				return "ghp_mock"
			}
			return ""
		},
		GitHubClientFactory: func(_ security.SensitiveString, _ string) github.Client { return stub },
	}

	// Missing --pkg should error.
	errCmd := NewRootCommandWithDeps(deps)
	errCmd.SetArgs([]string{"blast", "--repo", "octocat/hello"})
	if err := errCmd.Execute(); err == nil {
		t.Fatalf("expected error when --pkg and --advisory are omitted")
	}

	var out bytes.Buffer
	cmd := NewRootCommandWithDeps(deps)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"blast", "--repo", "octocat/hello", "--pkg", "evil-pkg@1.0.0", "--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("blast command failed: %v", err)
	}
	var report model.BlastReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("invalid blast JSON: %v", err)
	}
	if len(report.Packages) != 1 || report.Packages[0] != "evil-pkg@1.0.0" {
		t.Fatalf("unexpected blast report: %+v", report)
	}
}

type stubRotator struct{}

func (s *stubRotator) Name() string { return "stub-aws" }
func (s *stubRotator) PreflightCheck(_ context.Context, _ rotate.KeyTarget) (*rotate.PreflightInfo, error) {
	return &rotate.PreflightInfo{ResolvedOldKeyID: "AKIA_OLD", ExistingKeyCount: 1}, nil
}
func (s *stubRotator) MintKey(_ context.Context, _ rotate.KeyTarget) (*rotate.SecretMaterial, error) {
	return &rotate.SecretMaterial{
		KeyID: "AKIA_NEW",
		Values: map[string]*security.SensitiveBytes{
			"AWS_ACCESS_KEY_ID":     security.NewSensitiveBytes([]byte("AKIA_NEW")),
			"AWS_SECRET_ACCESS_KEY": security.NewSensitiveBytes([]byte("secret_new_value")),
		},
	}, nil
}
func (s *stubRotator) VerifyKey(_ context.Context, _ *rotate.SecretMaterial) error        { return nil }
func (s *stubRotator) DeactivateKey(_ context.Context, _ rotate.KeyTarget, _ string) error { return nil }
func (s *stubRotator) ReactivateKey(_ context.Context, _ rotate.KeyTarget, _ string) error { return nil }
func (s *stubRotator) DeleteKey(_ context.Context, _ rotate.KeyTarget, _ string) error     { return nil }

type stubSecretStore struct{}

func (s *stubSecretStore) Name() string                                             { return "stub-gh" }
func (s *stubSecretStore) PreflightScope(_ context.Context, _ rotate.StoreScope) error { return nil }
func (s *stubSecretStore) UpdateSecret(_ context.Context, _ rotate.StoreScope, _ string, _ *security.SensitiveBytes) error {
	return nil
}

func TestRotateDryRunApplyRollbackCleanupCommands(t *testing.T) {
	stateDir := t.TempDir()
	deps := Dependencies{
		LookupEnv: func(key string) string {
			if key == "GITHUB_TOKEN" {
				return "ghp_mock"
			}
			return ""
		},
		AWSRotatorFactory: func(_ context.Context, _, _ string, _, _ time.Duration) (rotate.CredentialProvider, error) {
			return &stubRotator{}, nil
		},
		SecretStoreFactory: func(_ security.SensitiveString, _ string) rotate.SecretStore {
			return &stubSecretStore{}
		},
	}

	// Dry-run plan
	var planOut bytes.Buffer
	planCmd := NewRootCommandWithDeps(deps)
	planCmd.SetOut(&planOut)
	planCmd.SetArgs([]string{"rotate", "--iam-user", "ci-bot", "--repo", "acme/api", "--dry-run", "--format", "json"})
	if err := planCmd.Execute(); err != nil {
		t.Fatalf("rotate --dry-run failed: %v", err)
	}
	var plan rotate.ExecutionPlan
	if err := json.Unmarshal(planOut.Bytes(), &plan); err != nil {
		t.Fatalf("invalid plan JSON: %v", err)
	}
	if plan.Target.OldKeyID != "AKIA_OLD" {
		t.Fatalf("unexpected plan: %+v", plan)
	}

	// Apply
	var applyOut bytes.Buffer
	applyCmd := NewRootCommandWithDeps(deps)
	applyCmd.SetOut(&applyOut)
	applyCmd.SetArgs([]string{"rotate", "--iam-user", "ci-bot", "--repo", "acme/api", "--apply", "--state-dir", stateDir, "--format", "json"})
	if err := applyCmd.Execute(); err != nil {
		t.Fatalf("rotate --apply failed: %v", err)
	}
	if strings.Contains(applyOut.String(), "secret_new_value") {
		t.Fatalf("rotate output leaked secret material")
	}
	var state rotate.RunState
	if err := json.Unmarshal(applyOut.Bytes(), &state); err != nil {
		t.Fatalf("invalid state JSON: %v", err)
	}
	if state.Stage != rotate.StageCompleted {
		t.Fatalf("expected COMPLETED stage, got %s", state.Stage)
	}

	// Cleanup
	var cleanOut bytes.Buffer
	cleanCmd := NewRootCommandWithDeps(deps)
	cleanCmd.SetOut(&cleanOut)
	cleanCmd.SetArgs([]string{"cleanup", "--run-id", state.RunID, "--state-dir", stateDir, "--format", "json"})
	if err := cleanCmd.Execute(); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	var cleaned rotate.RunState
	if err := json.Unmarshal(cleanOut.Bytes(), &cleaned); err != nil || cleaned.Stage != rotate.StageRevoked {
		t.Fatalf("unexpected cleanup result: %+v, err=%v", cleaned, err)
	}
}
