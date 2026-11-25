package model

import "time"

// SecretScope identifies where a GitHub Actions secret is defined.
type SecretScope string

const (
	ScopeOrg         SecretScope = "org"
	ScopeRepo        SecretScope = "repo"
	ScopeEnvironment SecretScope = "environment"
)

// RiskFlag categorizes security or hygiene risks associated with a secret exposure.
type RiskFlag string

const (
	RiskPullRequestTarget  RiskFlag = "pull_request_target"
	RiskWorkflowRun        RiskFlag = "workflow_run"
	RiskUnpinnedAction     RiskFlag = "unpinned_action"
	RiskSecretsInherit     RiskFlag = "secrets_inherit"
	RiskStaleSecret        RiskFlag = "stale_secret"
	RiskUnreferencedSecret RiskFlag = "unreferenced_secret"
	RiskUndefinedSecret    RiskFlag = "undefined_secret"
)

// StaleSecretAgeDays defines the default threshold after which a secret is flagged stale.
const StaleSecretAgeDays = 90

// ScanTarget records the target scope requested for a scan.
type ScanTarget struct {
	Org             string `json:"org,omitempty"`
	Repo            string `json:"repo,omitempty"`
	IncludeArchived bool   `json:"include_archived,omitempty"`
}

// SecretMetadata holds read-only metadata for a secret definition.
// It never contains raw secret values.
type SecretMetadata struct {
	Name        string      `json:"name"`
	Scope       SecretScope `json:"scope"`
	Owner       string      `json:"owner"`
	Repo        string      `json:"repo,omitempty"`
	Environment string      `json:"environment,omitempty"`
	Visibility  string      `json:"visibility,omitempty"`
	CreatedAt   time.Time   `json:"created_at,omitempty"`
	UpdatedAt   time.Time   `json:"updated_at,omitempty"`
	AgeDays     int         `json:"age_days"`
}

// WorkflowRef captures a single reference to a secret inside a GitHub Actions workflow.
type WorkflowRef struct {
	Repo         string     `json:"repo"`
	Path         string     `json:"path"`
	WorkflowName string     `json:"workflow_name,omitempty"`
	Triggers     []string   `json:"triggers,omitempty"`
	JobID        string     `json:"job_id,omitempty"`
	StepName     string     `json:"step_name,omitempty"`
	Location     string     `json:"location,omitempty"`
	RiskFlags    []RiskFlag `json:"risk_flags,omitempty"`
	UnpinnedUses []string   `json:"unpinned_uses,omitempty"`
}

// AWSFinding stores optional read-only AWS IAM metadata correlated with a secret.
type AWSFinding struct {
	IAMUser     string     `json:"iam_user,omitempty"`
	AccessKeyID string     `json:"access_key_id,omitempty"`
	AgeDays     int        `json:"age_days,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	Flags       []string   `json:"flags,omitempty"`
}

// SecretExposure aggregates all discovered definitions, workflow usages, and risks for one secret name.
type SecretExposure struct {
	SecretName   string           `json:"secret_name"`
	Scopes       []SecretScope    `json:"scopes,omitempty"`
	Definitions  []SecretMetadata `json:"definitions,omitempty"`
	Repos        []string         `json:"repos,omitempty"`
	Environments []string         `json:"environments,omitempty"`
	WorkflowRefs []WorkflowRef    `json:"workflow_refs,omitempty"`
	MaxAgeDays   int              `json:"max_age_days"`
	RiskFlags    []RiskFlag       `json:"risk_flags,omitempty"`
	AWS          *AWSFinding      `json:"aws,omitempty"`
}

// ScanSummary contains high-level counters for a completed scan.
type ScanSummary struct {
	ReposScanned    int `json:"repos_scanned"`
	ReposSkipped    int `json:"repos_skipped"`
	WorkflowsParsed int `json:"workflows_parsed"`
	UniqueSecrets   int `json:"unique_secrets"`
	StaleSecrets    int `json:"stale_secrets"`
	RiskyExposures  int `json:"risky_exposures"`
	WarningsCount   int `json:"warnings_count"`
}

// ScanWarning describes a non-fatal issue encountered during scanning (such as HTTP 403).
type ScanWarning struct {
	Scope   string `json:"scope"`
	Target  string `json:"target"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ScanReport is the top-level output of a read-only exposure scan.
type ScanReport struct {
	Target      ScanTarget       `json:"target"`
	GeneratedAt time.Time        `json:"generated_at"`
	Summary     ScanSummary      `json:"summary"`
	Exposures   []SecretExposure `json:"exposures"`
	Warnings    []ScanWarning    `json:"warnings,omitempty"`
}

// ComputeAgeDays returns whole days elapsed between updatedAt and now, clamped at 0.
func ComputeAgeDays(updatedAt, now time.Time) int {
	if updatedAt.IsZero() || now.Before(updatedAt) {
		return 0
	}
	return int(now.Sub(updatedAt) / (24 * time.Hour))
}
