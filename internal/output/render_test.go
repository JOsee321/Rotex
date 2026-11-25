package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/JOsee321/Rotex/internal/model"
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
