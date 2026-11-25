package blast

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/JOsee321/Rotex/internal/github"
	"github.com/JOsee321/Rotex/internal/lockfile"
	"github.com/JOsee321/Rotex/internal/model"
)

type mockBlastGitHub struct {
	repos      []github.Repository
	orgSecrets []model.SecretMetadata
	repoSec    map[string][]model.SecretMetadata
	workflows  map[string][]github.WorkflowFile
	lockfiles  map[string][]github.RepoFile
	runs       map[string][]github.WorkflowRun
}

func (m *mockBlastGitHub) ListOrgRepos(_ context.Context, _ string) ([]github.Repository, error) {
	return m.repos, nil
}

func (m *mockBlastGitHub) GetRepo(_ context.Context, owner, name string) (github.Repository, error) {
	full := owner + "/" + name
	for _, r := range m.repos {
		if r.FullName == full {
			return r, nil
		}
	}
	return github.Repository{}, &github.APIError{StatusCode: http.StatusNotFound}
}

func (m *mockBlastGitHub) ListOrgSecrets(_ context.Context, _ string) ([]model.SecretMetadata, error) {
	return m.orgSecrets, nil
}

func (m *mockBlastGitHub) ListRepoSecrets(_ context.Context, owner, repo string) ([]model.SecretMetadata, error) {
	return m.repoSec[owner+"/"+repo], nil
}

func (m *mockBlastGitHub) ListEnvironments(_ context.Context, _, _ string) ([]github.Environment, error) {
	return nil, nil
}

func (m *mockBlastGitHub) ListEnvironmentSecrets(_ context.Context, _, _, _ string) ([]model.SecretMetadata, error) {
	return nil, nil
}

func (m *mockBlastGitHub) ListWorkflowFiles(_ context.Context, owner, repo, _ string) ([]github.WorkflowFile, error) {
	return m.workflows[owner+"/"+repo], nil
}

func (m *mockBlastGitHub) ListRepoLockfiles(_ context.Context, owner, repo, _ string) ([]github.RepoFile, error) {
	return m.lockfiles[owner+"/"+repo], nil
}

func (m *mockBlastGitHub) ListWorkflowRuns(_ context.Context, owner, repo string, _ time.Time) ([]github.WorkflowRun, error) {
	return m.runs[owner+"/"+repo], nil
}

func TestBlastAnalyzePrioritizesExposedSecrets(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	gh := &mockBlastGitHub{
		repos: []github.Repository{
			{Owner: "acme", Name: "web", FullName: "acme/web", DefaultBranch: "main"},
			{Owner: "acme", Name: "api", FullName: "acme/api", DefaultBranch: "main"},
			{Owner: "acme", Name: "clean", FullName: "acme/clean", DefaultBranch: "main"},
		},
		orgSecrets: []model.SecretMetadata{
			{Name: "AWS_ACCESS_KEY_ID", Scope: model.ScopeOrg, Owner: "acme", UpdatedAt: now.Add(-100 * 24 * time.Hour)},
		},
		repoSec: map[string][]model.SecretMetadata{
			"acme/web":   {{Name: "VERCEL_TOKEN", Scope: model.ScopeRepo, Owner: "acme", Repo: "acme/web", UpdatedAt: now}},
			"acme/clean": {{Name: "CLEAN_ONLY_SECRET", Scope: model.ScopeRepo, Owner: "acme", Repo: "acme/clean", UpdatedAt: now}},
		},
		workflows: map[string][]github.WorkflowFile{
			"acme/web": {{
				Path:    ".github/workflows/deploy.yml",
				Content: []byte("on: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo deploy\n        env:\n          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n          VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}\n"),
			}},
			"acme/api": {{
				Path:    ".github/workflows/ci.yml",
				Content: []byte("on: pull_request_target\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test\n        env:\n          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n"),
			}},
		},
		lockfiles: map[string][]github.RepoFile{
			"acme/web": {{
				Path:    "package-lock.json",
				Content: []byte(`{"lockfileVersion":3,"packages":{"node_modules/shai-hulud":{"version":"1.2.3"}}}`),
			}},
			"acme/api": {{
				Path:    "pnpm-lock.yaml",
				Content: []byte("packages:\n  'shai-hulud@1.2.3': {}\n"),
			}},
			"acme/clean": {{
				Path:    "package-lock.json",
				Content: []byte(`{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}`),
			}},
		},
		runs: map[string][]github.WorkflowRun{
			"acme/web": {{ID: 1, Path: ".github/workflows/deploy.yml", CreatedAt: now.Add(-2 * time.Hour)}},
			"acme/api": {{ID: 2, Path: ".github/workflows/ci.yml", CreatedAt: now.Add(-4 * time.Hour)}},
		},
	}

	svc := NewService(gh, WithClock(func() time.Time { return now }))
	report, err := svc.Analyze(context.Background(), Request{
		Target:   model.ScanTarget{Org: "acme"},
		Packages: []lockfile.PackageSpec{{Name: "shai-hulud", Version: "1.2.3"}},
		Since:    72 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(report.Matches) != 2 {
		t.Fatalf("expected 2 lockfile matches, got %+v", report.Matches)
	}
	if len(report.RotationQueue) != 2 {
		t.Fatalf("expected 2 exposed secrets in rotation queue (CLEAN_ONLY_SECRET excluded), got %+v", report.RotationQueue)
	}
	if report.RotationQueue[0].SecretName != "AWS_ACCESS_KEY_ID" {
		t.Fatalf("expected AWS_ACCESS_KEY_ID ranked #1, got %+v", report.RotationQueue[0])
	}
	if report.RotationQueue[0].Severity != "CRITICAL" {
		t.Fatalf("expected CRITICAL severity for #1, got %s", report.RotationQueue[0].Severity)
	}
}
