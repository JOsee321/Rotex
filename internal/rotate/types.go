package rotate

import (
	"context"
	"time"

	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/security"
)

// Stage represents the lifecycle state of a rotation run.
type Stage string

const (
	StagePreflight         Stage = "PREFLIGHT"
	StageMint              Stage = "MINT"
	StageInject            Stage = "INJECT"
	StageVerify            Stage = "VERIFY"
	StageDeactivate        Stage = "DEACTIVATE"
	StageCompleted         Stage = "COMPLETED"
	StageRevoked           Stage = "REVOKED"
	StageFailedRecoverable Stage = "FAILED_RECOVERABLE"
	StageRolledBack        Stage = "ROLLED_BACK"
)

// KeyTarget identifies the upstream credential resource to rotate.
type KeyTarget struct {
	IAMUser  string `json:"iam_user"`
	OldKeyID string `json:"old_key_id,omitempty"`
}

// SecretMaterial holds newly minted credential values in memory only.
// Callers must always invoke Wipe via defer.
type SecretMaterial struct {
	KeyID  string
	Values map[string]*security.SensitiveBytes
}

// Wipe zeros all in-memory credential material.
func (m *SecretMaterial) Wipe() {
	if m == nil {
		return
	}
	for _, v := range m.Values {
		if v != nil {
			v.Wipe()
		}
	}
	m.Values = nil
}

// PreflightInfo summarizes read-only provider preconditions before minting.
type PreflightInfo struct {
	ResolvedOldKeyID string   `json:"resolved_old_key_id"`
	ExistingKeyCount int      `json:"existing_key_count"`
	ExistingKeyIDs   []string `json:"existing_key_ids,omitempty"`
}

// CredentialProvider manages the lifecycle of credentials at their source vendor.
type CredentialProvider interface {
	Name() string
	PreflightCheck(ctx context.Context, target KeyTarget) (*PreflightInfo, error)
	MintKey(ctx context.Context, target KeyTarget) (*SecretMaterial, error)
	VerifyKey(ctx context.Context, mat *SecretMaterial) error
	DeactivateKey(ctx context.Context, target KeyTarget, keyID string) error
	ReactivateKey(ctx context.Context, target KeyTarget, keyID string) error
	DeleteKey(ctx context.Context, target KeyTarget, keyID string) error
}

// StoreScope identifies a GitHub Actions secret target (repo, environment, or org).
type StoreScope struct {
	Scope       model.SecretScope `json:"scope"`
	Org         string            `json:"org,omitempty"`
	Repo        string            `json:"repo,omitempty"`
	Environment string            `json:"environment,omitempty"`
}

// Label returns a human-readable identifier for the target scope.
func (s StoreScope) Label() string {
	switch s.Scope {
	case model.ScopeOrg:
		return "org:" + s.Org
	case model.ScopeEnvironment:
		return s.Repo + "/" + s.Environment
	default:
		return s.Repo
	}
}

// SecretStore writes encrypted secrets into a downstream CI/CD store.
type SecretStore interface {
	Name() string
	PreflightScope(ctx context.Context, scope StoreScope) error
	UpdateSecret(ctx context.Context, scope StoreScope, name string, value *security.SensitiveBytes) error
}

// TargetInjectionStatus records whether one downstream scope succeeded or failed.
type TargetInjectionStatus struct {
	Target StoreScope `json:"target"`
	Status string     `json:"status"`
	Error  string     `json:"error,omitempty"`
}

// ExecutionPlan describes the deterministic dry-run plan before any mutations occur.
type ExecutionPlan struct {
	Provider        string          `json:"provider"`
	Target          KeyTarget       `json:"target"`
	Preflight       *PreflightInfo  `json:"preflight"`
	SecretNames     []string        `json:"secret_names"`
	StoreTargets    []StoreScope    `json:"store_targets"`
	ImmediateDelete bool            `json:"immediate_delete"`
	Warnings        []string        `json:"warnings,omitempty"`
	GeneratedAt     time.Time       `json:"generated_at"`
}

// RunState is persisted to .rotex/state/<run-id>.json using metadata and IDs only.
// It must never store raw secret values.
type RunState struct {
	RunID           string                  `json:"run_id"`
	Provider        string                  `json:"provider"`
	Target          KeyTarget               `json:"target"`
	OldKeyID        string                  `json:"old_key_id"`
	NewKeyID        string                  `json:"new_key_id,omitempty"`
	Stage           Stage                   `json:"stage"`
	SecretNames     []string                `json:"secret_names"`
	Targets         []TargetInjectionStatus `json:"targets"`
	OldDeactivated  bool                    `json:"old_deactivated"`
	NewDeleted      bool                    `json:"new_deleted"`
	OldDeleted      bool                    `json:"old_deleted"`
	ImmediateDelete bool                    `json:"immediate_delete"`
	Error           string                  `json:"error,omitempty"`
	CreatedAt       time.Time               `json:"created_at"`
	UpdatedAt       time.Time               `json:"updated_at"`
}
