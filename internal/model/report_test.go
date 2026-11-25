package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestComputeAgeDays(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		updatedAt time.Time
		want      int
	}{
		{name: "zero time", updatedAt: time.Time{}, want: 0},
		{name: "future time clamped", updatedAt: now.Add(48 * time.Hour), want: 0},
		{name: "same day", updatedAt: now.Add(-12 * time.Hour), want: 0},
		{name: "exact 95 days", updatedAt: now.Add(-95 * 24 * time.Hour), want: 95},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ComputeAgeDays(tc.updatedAt, now); got != tc.want {
				t.Fatalf("ComputeAgeDays() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestScanReportJSONSerialization(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	report := ScanReport{
		Target:      ScanTarget{Org: "acme"},
		GeneratedAt: now,
		Summary:     ScanSummary{ReposScanned: 1, UniqueSecrets: 1},
		Exposures: []SecretExposure{
			{
				SecretName: "AWS_ACCESS_KEY_ID",
				Scopes:     []SecretScope{ScopeRepo},
				MaxAgeDays: 120,
				RiskFlags:  []RiskFlag{RiskStaleSecret},
			},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded ScanReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.Target.Org != "acme" || len(decoded.Exposures) != 1 || decoded.Exposures[0].SecretName != "AWS_ACCESS_KEY_ID" {
		t.Fatalf("unexpected decoded report: %+v", decoded)
	}
}
