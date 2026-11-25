package workflow

import (
	"slices"
	"testing"

	"github.com/JOsee321/Rotex/internal/model"
)

func TestIsWorkflowFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{".github/workflows/ci.yml", true},
		{".github/workflows/deploy.yaml", true},
		{".github/workflows/RELEASE.YML", true},
		{".github/workflows/nested/sub.yml", false},
		{".github/actions/my-action/action.yml", false},
		{".github/workflows/README.md", false},
	}

	for _, tc := range tests {
		if got := IsWorkflowFile(tc.path); got != tc.want {
			t.Errorf("IsWorkflowFile(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestParseWorkflowReferencesAndRisks(t *testing.T) {
	const rawYAML = `
name: Production Deploy
on:
  push:
    branches: [main]
  pull_request_target:
    types: [opened]

env:
  GLOBAL_TOKEN: ${{ secrets.GLOBAL_API_KEY }}

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Auth AWS
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
      - name: Publish
        env:
          GH: ${{ secrets.GITHUB_TOKEN }}
        run: |
          echo "${{ secrets.DEPLOY_KEY || secrets.FALLBACK_KEY }}"
`

	parsed, err := Parse(".github/workflows/deploy.yaml", []byte(rawYAML))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed.Name != "Production Deploy" {
		t.Fatalf("unexpected workflow name: %q", parsed.Name)
	}
	if !slices.Contains(parsed.Triggers, "pull_request_target") {
		t.Fatalf("expected pull_request_target trigger, got %v", parsed.Triggers)
	}
	if !slices.Contains(parsed.WorkflowRiskFlags, model.RiskPullRequestTarget) {
		t.Fatalf("expected pull_request_target risk flag, got %v", parsed.WorkflowRiskFlags)
	}

	gotSecrets := map[string]SecretUsage{}
	for _, ref := range parsed.References {
		if ref.SecretName == "GITHUB_TOKEN" {
			t.Fatalf("built-in GITHUB_TOKEN should be ignored")
		}
		gotSecrets[ref.SecretName] = ref
	}

	for _, expected := range []string{"GLOBAL_API_KEY", "NPM_TOKEN", "AWS_ROLE_ARN", "DEPLOY_KEY", "FALLBACK_KEY"} {
		usage, ok := gotSecrets[expected]
		if !ok {
			t.Fatalf("expected secret %s to be detected", expected)
		}
		if !slices.Contains(usage.RiskFlags, model.RiskPullRequestTarget) {
			t.Fatalf("secret %s missing pull_request_target flag: %v", expected, usage.RiskFlags)
		}
		if !slices.Contains(usage.RiskFlags, model.RiskUnpinnedAction) {
			t.Fatalf("secret %s missing unpinned_action flag: %v", expected, usage.RiskFlags)
		}
		if !slices.Equal(usage.UnpinnedUses, []string{"actions/checkout@v4"}) {
			t.Fatalf("secret %s unexpected unpinned uses: %v", expected, usage.UnpinnedUses)
		}
	}
}

func TestParseWorkflowSecretsInheritAndWorkflowRun(t *testing.T) {
	const rawYAML = `
name: Reusable Caller
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  call-reusable:
    uses: org/shared/.github/workflows/release.yml@main
    secrets: inherit
    with:
      env_name: prod
`

	parsed, err := Parse(".github/workflows/reusable.yml", []byte(rawYAML))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if !slices.Contains(parsed.WorkflowRiskFlags, model.RiskWorkflowRun) {
		t.Fatalf("expected workflow_run risk flag, got %v", parsed.WorkflowRiskFlags)
	}
	if len(parsed.InheritJobs) != 1 {
		t.Fatalf("expected 1 inherit job, got %d", len(parsed.InheritJobs))
	}

	job := parsed.InheritJobs[0]
	if job.JobID != "call-reusable" {
		t.Fatalf("unexpected job ID: %q", job.JobID)
	}
	for _, wantFlag := range []model.RiskFlag{model.RiskWorkflowRun, model.RiskUnpinnedAction, model.RiskSecretsInherit} {
		if !slices.Contains(job.RiskFlags, wantFlag) {
			t.Fatalf("inherit job missing flag %s: %v", wantFlag, job.RiskFlags)
		}
	}
}

func TestParseWorkflowPinnedOnlyHasNoUnpinnedFlag(t *testing.T) {
	const rawYAML = `
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ./local-action
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: echo "ok"
        env:
          API_KEY: ${{ secrets.api_key }}
`

	parsed, err := Parse(".github/workflows/ci.yml", []byte(rawYAML))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(parsed.References) != 1 {
		t.Fatalf("expected 1 reference, got %d", len(parsed.References))
	}
	ref := parsed.References[0]
	if ref.SecretName != "API_KEY" {
		t.Fatalf("expected normalized uppercase API_KEY, got %q", ref.SecretName)
	}
	if len(ref.RiskFlags) != 0 {
		t.Fatalf("expected no risk flags for pinned workflow, got %v", ref.RiskFlags)
	}
}

func TestParseWorkflowErrorsAndEmpty(t *testing.T) {
	empty, err := Parse(".github/workflows/empty.yml", []byte("   \n"))
	if err != nil {
		t.Fatalf("expected empty workflow not to error, got %v", err)
	}
	if len(empty.References) != 0 {
		t.Fatalf("expected 0 refs in empty workflow")
	}

	if _, err := Parse(".github/workflows/bad.yml", []byte(":::invalid: [")); err == nil {
		t.Fatalf("expected error on malformed YAML")
	}
}
