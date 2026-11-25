package scanner

import (
	"context"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JOsee321/Rotex/internal/aws"
	"github.com/JOsee321/Rotex/internal/github"
	"github.com/JOsee321/Rotex/internal/model"
)

type mockAWSInspector struct {
	report *aws.AuditReport
	err    error
}

func (m *mockAWSInspector) Inspect(_ context.Context, _ time.Duration) (*aws.AuditReport, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.report, nil
}

type mockGitHubClient struct {
	repos      []github.Repository
	orgSecrets []model.SecretMetadata
	orgSecErr  error

	repoSecrets map[string][]model.SecretMetadata
	repoSecErr  map[string]error
	envs        map[string][]github.Environment
	envsErr     map[string]error
	envSecrets  map[string][]model.SecretMetadata
	envSecErr   map[string]error
	workflows   map[string][]github.WorkflowFile

	activeWorkers atomic.Int32
	maxConcurrent atomic.Int32
	workDelay     time.Duration
}

func (m *mockGitHubClient) ListOrgRepos(_ context.Context, _ string) ([]github.Repository, error) {
	return m.repos, nil
}

func (m *mockGitHubClient) GetRepo(_ context.Context, owner, name string) (github.Repository, error) {
	full := owner + "/" + name
	for _, r := range m.repos {
		if r.FullName == full {
			return r, nil
		}
	}
	return github.Repository{}, &github.APIError{StatusCode: http.StatusNotFound, Endpoint: "/repos/" + full}
}

func (m *mockGitHubClient) ListOrgSecrets(_ context.Context, _ string) ([]model.SecretMetadata, error) {
	if m.orgSecErr != nil {
		return nil, m.orgSecErr
	}
	return m.orgSecrets, nil
}

func (m *mockGitHubClient) ListRepoSecrets(_ context.Context, owner, repo string) ([]model.SecretMetadata, error) {
	cur := m.activeWorkers.Add(1)
	defer m.activeWorkers.Add(-1)
	for {
		prev := m.maxConcurrent.Load()
		if cur <= prev || m.maxConcurrent.CompareAndSwap(prev, cur) {
			break
		}
	}
	if m.workDelay > 0 {
		time.Sleep(m.workDelay)
	}

	full := owner + "/" + repo
	if err := m.repoSecErr[full]; err != nil {
		return nil, err
	}
	return m.repoSecrets[full], nil
}

func (m *mockGitHubClient) ListEnvironments(_ context.Context, owner, repo string) ([]github.Environment, error) {
	full := owner + "/" + repo
	if err := m.envsErr[full]; err != nil {
		return nil, err
	}
	return m.envs[full], nil
}

func (m *mockGitHubClient) ListEnvironmentSecrets(_ context.Context, owner, repo, env string) ([]model.SecretMetadata, error) {
	key := owner + "/" + repo + "/" + env
	if err := m.envSecErr[key]; err != nil {
		return nil, err
	}
	return m.envSecrets[key], nil
}

func (m *mockGitHubClient) ListWorkflowFiles(_ context.Context, owner, repo, _ string) ([]github.WorkflowFile, error) {
	return m.workflows[owner+"/"+repo], nil
}

func (m *mockGitHubClient) ListRepoLockfiles(_ context.Context, _, _, _ string) ([]github.RepoFile, error) {
	return nil, nil
}

func (m *mockGitHubClient) ListWorkflowRuns(_ context.Context, _, _ string, _ time.Time) ([]github.WorkflowRun, error) {
	return nil, nil
}

func TestScanOrgGracefulDegradationAndInherit(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	client := &mockGitHubClient{
		repos: []github.Repository{
			{Owner: "acme", Name: "api", FullName: "acme/api", DefaultBranch: "main"},
			{Owner: "acme", Name: "old-repo", FullName: "acme/old-repo", DefaultBranch: "main", Archived: true},
		},
		orgSecErr: &github.APIError{StatusCode: http.StatusForbidden, Message: "forbidden", Endpoint: "/orgs/acme/actions/secrets"},
		repoSecrets: map[string][]model.SecretMetadata{
			"acme/api": {
				{
					Name:      "AWS_ACCESS_KEY_ID",
					Scope:     model.ScopeRepo,
					Owner:     "acme",
					Repo:      "acme/api",
					UpdatedAt: now.Add(-120 * 24 * time.Hour),
				},
				{
					Name:      "UNUSED_KEY",
					Scope:     model.ScopeRepo,
					Owner:     "acme",
					Repo:      "acme/api",
					UpdatedAt: now.Add(-10 * 24 * time.Hour),
				},
			},
		},
		envs: map[string][]github.Environment{
			"acme/api": {{Name: "prod"}},
		},
		envSecErr: map[string]error{
			"acme/api/prod": &github.APIError{StatusCode: http.StatusForbidden, Endpoint: "/repos/acme/api/environments/prod/secrets"},
		},
		workflows: map[string][]github.WorkflowFile{
			"acme/api": {
				{
					Path: ".github/workflows/deploy.yml",
					Content: []byte(`
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo deploy
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          MISSING: ${{ secrets.MISSING_ORG_SECRET }}
`),
				},
				{
					Path: ".github/workflows/reusable.yaml",
					Content: []byte(`
on: push
jobs:
  release:
    uses: acme/shared/.github/workflows/rel.yml@main
    secrets: inherit
`),
				},
			},
		},
	}

	svc := NewService(client, WithClock(func() time.Time { return now }))
	report, err := svc.Scan(context.Background(), model.ScanTarget{Org: "acme"})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if report.Summary.ReposScanned != 1 || report.Summary.ReposSkipped != 1 {
		t.Fatalf("unexpected repo counts: %+v", report.Summary)
	}
	if report.Summary.WarningsCount != 2 {
		t.Fatalf("expected 2 graceful 403 warnings, got %d: %+v", report.Summary.WarningsCount, report.Warnings)
	}

	byName := map[string]model.SecretExposure{}
	for _, exp := range report.Exposures {
		byName[exp.SecretName] = exp
	}

	awsExp := byName["AWS_ACCESS_KEY_ID"]
	for _, want := range []model.RiskFlag{
		model.RiskPullRequestTarget,
		model.RiskUnpinnedAction,
		model.RiskSecretsInherit,
		model.RiskStaleSecret,
	} {
		if !slices.Contains(awsExp.RiskFlags, want) {
			t.Fatalf("AWS_ACCESS_KEY_ID missing risk flag %s: %v", want, awsExp.RiskFlags)
		}
	}

	if slices.Contains(byName["MISSING_ORG_SECRET"].RiskFlags, model.RiskUndefinedSecret) {
		t.Fatalf("should not falsely flag MISSING_ORG_SECRET as undefined_secret when org/env secrets returned 403")
	}
}

func TestScanFlagsUndefinedSecretOnlyWhenInventoryReadableAndFailsOnRateLimit(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	client := &mockGitHubClient{
		repos: []github.Repository{
			{Owner: "acme", Name: "api", FullName: "acme/api", DefaultBranch: "main"},
		},
		workflows: map[string][]github.WorkflowFile{
			"acme/api": {
				{
					Path:    ".github/workflows/ci.yml",
					Content: []byte("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n        env:\n          NOPE: ${{ secrets.TRULY_UNDEFINED }}\n"),
				},
			},
		},
	}

	svc := NewService(client, WithClock(func() time.Time { return now }))
	report, err := svc.Scan(context.Background(), model.ScanTarget{Repo: "acme/api"})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if !slices.Contains(report.Exposures[0].RiskFlags, model.RiskUndefinedSecret) {
		t.Fatalf("expected undefined_secret when inventory is readable, got %v", report.Exposures[0].RiskFlags)
	}

	// Rate limit 403 must return an error instead of degrading silently.
	rlClient := &mockGitHubClient{
		repos: []github.Repository{
			{Owner: "acme", Name: "api", FullName: "acme/api", DefaultBranch: "main"},
		},
		repoSecErr: map[string]error{
			"acme/api": &github.APIError{
				StatusCode: http.StatusForbidden,
				Message:    "API rate limit exceeded",
				Endpoint:   "/repos/acme/api/actions/secrets",
			},
		},
	}
	rlSvc := NewService(rlClient, WithAllowUnauthenticated(true))
	if _, err := rlSvc.Scan(context.Background(), model.ScanTarget{Repo: "acme/api"}); err == nil || !github.IsRateLimited(err) {
		t.Fatalf("expected fatal rate-limit error, got %v", err)
	}
}

func TestScanBoundedConcurrency(t *testing.T) {
	var repos []github.Repository
	for i := 0; i < 12; i++ {
		name := "repo-" + string(rune('a'+i))
		repos = append(repos, github.Repository{
			Owner: "acme", Name: name, FullName: "acme/" + name, DefaultBranch: "main",
		})
	}
	client := &mockGitHubClient{
		repos:     repos,
		workDelay: 15 * time.Millisecond,
	}

	svc := NewService(client, WithConcurrency(3))
	if _, err := svc.Scan(context.Background(), model.ScanTarget{Org: "acme"}); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if max := client.maxConcurrent.Load(); max > 3 || max < 2 {
		t.Fatalf("expected max concurrency in [2,3], got %d", max)
	}
}

func TestScanSingleRepoWithoutOrgAccess(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	client := &mockGitHubClient{
		repos: []github.Repository{
			{Owner: "octocat", Name: "hello", FullName: "octocat/hello", DefaultBranch: "main"},
		},
		orgSecErr: &github.APIError{StatusCode: http.StatusForbidden, Endpoint: "should-not-be-called"},
		repoSecrets: map[string][]model.SecretMetadata{
			"octocat/hello": {
				{Name: "NPM_TOKEN", Scope: model.ScopeRepo, Owner: "octocat", Repo: "octocat/hello", UpdatedAt: now},
			},
		},
	}

	svc := NewService(client, WithClock(func() time.Time { return now }))
	report, err := svc.Scan(context.Background(), model.ScanTarget{Repo: "octocat/hello"})
	if err != nil {
		t.Fatalf("single-repo scan failed: %v", err)
	}
	if report.Summary.UniqueSecrets != 1 || report.Summary.WarningsCount != 0 {
		t.Fatalf("unexpected single-repo summary: %+v, warnings: %+v", report.Summary, report.Warnings)
	}
	if !slices.Contains(report.Exposures[0].RiskFlags, model.RiskUnreferencedSecret) {
		t.Fatalf("expected unreferenced_secret flag, got %v", report.Exposures[0].RiskFlags)
	}
}

func TestScanWithAWSCorrelation(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	client := &mockGitHubClient{
		repos: []github.Repository{
			{Owner: "acme", Name: "api", FullName: "acme/api", DefaultBranch: "main"},
		},
		repoSecrets: map[string][]model.SecretMetadata{
			"acme/api": {
				{Name: "AWS_ACCESS_KEY_ID", Scope: model.ScopeRepo, Owner: "acme", Repo: "acme/api", UpdatedAt: now.Add(-10 * 24 * time.Hour)},
			},
		},
		workflows: map[string][]github.WorkflowFile{
			"acme/api": {
				{
					Path:    ".github/workflows/ci.yml",
					Content: []byte("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: echo hi\n        env:\n          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n"),
				},
			},
		},
	}

	awsInsp := &mockAWSInspector{
		report: &aws.AuditReport{
			Keys: []aws.AccessKeyAudit{
				{
					UserName:          "ci-deployer",
					AccessKeyID:       "AKIAEXAMPLE123",
					Status:            "Active",
					AgeDays:           150,
					Stale:             true,
					Overprivileged:    true,
					GitHubRunnerSeen:  true,
					ExternalUsageSeen: true,
					ExternalSources:   []string{"aws-cli@198.51.100.1"},
				},
			},
		},
	}

	svc := NewService(client, WithClock(func() time.Time { return now }), WithAWSInspector(awsInsp))
	report, err := svc.Scan(context.Background(), model.ScanTarget{Repo: "acme/api"})
	if err != nil {
		t.Fatalf("Scan with AWS failed: %v", err)
	}
	if len(report.AWSKeys) != 1 {
		t.Fatalf("expected 1 AWS key, got %d", len(report.AWSKeys))
	}
	exp := report.Exposures[0]
	if exp.AWS == nil || exp.AWS.AccessKeyID != "AKIAEXAMPLE123" {
		t.Fatalf("expected correlated AWS finding, got %+v", exp.AWS)
	}
	for _, want := range []model.RiskFlag{model.RiskAWSStaleKey, model.RiskAWSOverprivileged, model.RiskAWSExternalUsage} {
		if !slices.Contains(exp.RiskFlags, want) {
			t.Fatalf("missing AWS risk flag %s: %v", want, exp.RiskFlags)
		}
	}
}
