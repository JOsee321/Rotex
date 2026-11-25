package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/rotate"
)

func sampleReport() *model.ScanReport {
	return &model.ScanReport{
		Target:      model.ScanTarget{Org: "acme"},
		GeneratedAt: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC),
		Summary: model.ScanSummary{
			ReposScanned:    2,
			WorkflowsParsed: 3,
			UniqueSecrets:   1,
			StaleSecrets:    1,
			RiskyExposures:  1,
			WarningsCount:   1,
		},
		Exposures: []model.SecretExposure{
			{
				SecretName: "AWS_ACCESS_KEY_ID",
				Scopes:     []model.SecretScope{model.ScopeRepo},
				Definitions: []model.SecretMetadata{
					{Name: "AWS_ACCESS_KEY_ID", Scope: model.ScopeRepo, AgeDays: 120},
				},
				Repos: []string{"acme/api", "acme/web", "acme/worker"},
				WorkflowRefs: []model.WorkflowRef{
					{Repo: "acme/api", Path: ".github/workflows/deploy.yml"},
					{Repo: "acme/api", Path: ".github/workflows/deploy.yml"},
					{Repo: "acme/web", Path: ".github/workflows/ci.yml"},
				},
				MaxAgeDays: 120,
				RiskFlags:  []model.RiskFlag{model.RiskPullRequestTarget, model.RiskStaleSecret},
			},
		},
		Warnings: []model.ScanWarning{
			{Scope: "org", Target: "acme", Code: "permission_denied", Message: "HTTP 403"},
		},
	}
}

func TestParseFormat(t *testing.T) {
	for _, valid := range []string{"", "table", "JSON", "markdown"} {
		if _, err := ParseFormat(valid); err != nil {
			t.Fatalf("ParseFormat(%q) unexpected error: %v", valid, err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Fatalf("expected error for unsupported format")
	}
}

func TestRenderFormats(t *testing.T) {
	report := sampleReport()

	var tableBuf bytes.Buffer
	if err := Render(&tableBuf, report, Options{Format: FormatTable, NoColor: true}); err != nil {
		t.Fatalf("render table failed: %v", err)
	}
	tableOut := tableBuf.String()
	if strings.Contains(tableOut, "\033[") {
		t.Fatalf("expected no ANSI escape sequences with NoColor=true")
	}
	for _, want := range []string{"AWS_ACCESS_KEY_ID", "acme/api, acme/web (+1)", "pull_request_target,stale_secret", "Warnings:"} {
		if !strings.Contains(tableOut, want) {
			t.Fatalf("table output missing %q:\n%s", want, tableOut)
		}
	}

	var mdBuf bytes.Buffer
	if err := Render(&mdBuf, report, Options{Format: FormatMarkdown}); err != nil {
		t.Fatalf("render markdown failed: %v", err)
	}
	if !strings.Contains(mdBuf.String(), "| `AWS_ACCESS_KEY_ID` |") || !strings.Contains(mdBuf.String(), "### Warnings") {
		t.Fatalf("unexpected markdown output:\n%s", mdBuf.String())
	}

	var jsonBuf bytes.Buffer
	if err := Render(&jsonBuf, report, Options{Format: FormatJSON}); err != nil {
		t.Fatalf("render json failed: %v", err)
	}
	var decoded model.ScanReport
	if err := json.Unmarshal(jsonBuf.Bytes(), &decoded); err != nil {
		t.Fatalf("rendered JSON invalid: %v", err)
	}
	if decoded.Summary.UniqueSecrets != 1 {
		t.Fatalf("unexpected JSON summary: %+v", decoded.Summary)
	}
}

func TestRenderBlastFormats(t *testing.T) {
	report := &model.BlastReport{
		Target:      model.ScanTarget{Org: "acme"},
		GeneratedAt: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC),
		SinceHours:  72,
		Packages:    []string{"evil@1.2.3"},
		Matches: []model.CompromisedMatch{
			{Repo: "acme/web", Ecosystem: "npm", Package: "evil", Version: "1.2.3", Lockfile: "package-lock.json"},
		},
		RotationQueue: []model.ExposedSecretPriority{
			{
				Priority:       1,
				Severity:       "CRITICAL",
				Score:          95,
				SecretName:     "AWS_ACCESS_KEY_ID",
				AffectedRepos:  []string{"acme/web"},
				RecentRunCount: 2,
				Reason:         "used in 1 affected repo(s)",
			},
		},
	}

	var tableBuf bytes.Buffer
	if err := RenderBlast(&tableBuf, report, Options{Format: FormatTable, NoColor: true}); err != nil {
		t.Fatalf("RenderBlast table failed: %v", err)
	}
	if !strings.Contains(tableBuf.String(), "AWS_ACCESS_KEY_ID") || !strings.Contains(tableBuf.String(), "CRITICAL") {
		t.Fatalf("unexpected blast table output:\n%s", tableBuf.String())
	}

	var mdBuf bytes.Buffer
	if err := RenderBlast(&mdBuf, report, Options{Format: FormatMarkdown}); err != nil {
		t.Fatalf("RenderBlast markdown failed: %v", err)
	}
	if !strings.Contains(mdBuf.String(), "| #1 | **CRITICAL** | `AWS_ACCESS_KEY_ID` |") {
		t.Fatalf("unexpected blast markdown output:\n%s", mdBuf.String())
	}

	var jsonBuf bytes.Buffer
	if err := RenderBlast(&jsonBuf, report, Options{Format: FormatJSON}); err != nil {
		t.Fatalf("RenderBlast json failed: %v", err)
	}
	var decoded model.BlastReport
	if err := json.Unmarshal(jsonBuf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid blast JSON: %v", err)
	}
	if len(decoded.RotationQueue) != 1 {
		t.Fatalf("unexpected decoded blast report: %+v", decoded)
	}
}

func TestRenderRotationPlanAndState(t *testing.T) {
	plan := &rotate.ExecutionPlan{
		Provider: "aws-iam",
		Target:   rotate.KeyTarget{IAMUser: "ci-bot", OldKeyID: "AKIA_OLD"},
		Preflight: &rotate.PreflightInfo{
			ResolvedOldKeyID: "AKIA_OLD",
			ExistingKeyCount: 1,
		},
		SecretNames:  []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"},
		StoreTargets: []rotate.StoreScope{{Scope: model.ScopeRepo, Repo: "acme/api"}},
	}

	var planBuf bytes.Buffer
	if err := RenderRotationPlan(&planBuf, plan, Options{Format: FormatTable}); err != nil {
		t.Fatalf("RenderRotationPlan failed: %v", err)
	}
	if !strings.Contains(planBuf.String(), "[DRY-RUN]") || !strings.Contains(planBuf.String(), "AKIA_OLD") {
		t.Fatalf("unexpected plan output:\n%s", planBuf.String())
	}

	state := &rotate.RunState{
		RunID:          "rot-1",
		Target:         rotate.KeyTarget{IAMUser: "ci-bot"},
		OldKeyID:       "AKIA_OLD",
		NewKeyID:       "AKIA_NEW",
		Stage:          rotate.StageCompleted,
		OldDeactivated: true,
		Targets: []rotate.TargetInjectionStatus{
			{Target: rotate.StoreScope{Scope: model.ScopeRepo, Repo: "acme/api"}, Status: "INJECTED"},
		},
	}

	var stateBuf bytes.Buffer
	if err := RenderRunState(&stateBuf, state, Options{Format: FormatMarkdown}); err != nil {
		t.Fatalf("RenderRunState failed: %v", err)
	}
	if !strings.Contains(stateBuf.String(), "rot-1") || !strings.Contains(stateBuf.String(), "COMPLETED") {
		t.Fatalf("unexpected state output:\n%s", stateBuf.String())
	}
}

func TestRenderSanitizesANSIAndControlChars(t *testing.T) {
	report := &model.ScanReport{
		Target:      model.ScanTarget{Org: "acme"},
		GeneratedAt: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC),
		Warnings: []model.ScanWarning{
			{
				Scope:   "workflow",
				Target:  "acme/evil|repo",
				Code:    "parse_error",
				Message: "bad\x1b[31mANSI\x1b]2;pwned\x07\nline",
			},
		},
	}

	var tableBuf bytes.Buffer
	if err := Render(&tableBuf, report, Options{Format: FormatTable, NoColor: true}); err != nil {
		t.Fatalf("Render table failed: %v", err)
	}
	if strings.Contains(tableBuf.String(), "\x1b") || strings.Contains(tableBuf.String(), "\x07") {
		t.Fatalf("table output leaked terminal escape characters: %q", tableBuf.String())
	}

	var mdBuf bytes.Buffer
	if err := Render(&mdBuf, report, Options{Format: FormatMarkdown}); err != nil {
		t.Fatalf("Render markdown failed: %v", err)
	}
	if strings.Contains(mdBuf.String(), "\x1b") || !strings.Contains(mdBuf.String(), `acme/evil\|repo`) {
		t.Fatalf("markdown output unsafe or unescaped: %q", mdBuf.String())
	}
}
