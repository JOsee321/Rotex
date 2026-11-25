package model

import "time"

// CompromisedMatch records a dependency lockfile hit inside a repository.
type CompromisedMatch struct {
	Repo      string `json:"repo"`
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Version   string `json:"version"`
	Lockfile  string `json:"lockfile"`
}

// ExposedSecretPriority represents one secret ranked for incident rotation.
type ExposedSecretPriority struct {
	Priority        int           `json:"priority"`
	Severity        string        `json:"severity"`
	Score           int           `json:"score"`
	SecretName      string        `json:"secret_name"`
	Scopes          []SecretScope `json:"scopes,omitempty"`
	AffectedRepos   []string      `json:"affected_repos"`
	RecentRunCount  int           `json:"recent_run_count"`
	RecentWorkflows []string      `json:"recent_workflows,omitempty"`
	RiskFlags       []RiskFlag    `json:"risk_flags,omitempty"`
	Reason          string        `json:"reason"`
}

// BlastReport is the output of an incident blast radius analysis (`rotex blast`).
type BlastReport struct {
	Target        ScanTarget              `json:"target"`
	GeneratedAt   time.Time               `json:"generated_at"`
	SinceHours    int                     `json:"since_hours"`
	Packages      []string                `json:"packages"`
	Matches       []CompromisedMatch      `json:"matches"`
	RotationQueue []ExposedSecretPriority `json:"rotation_queue"`
	Warnings      []ScanWarning           `json:"warnings,omitempty"`
}
