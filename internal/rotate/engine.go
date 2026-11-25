package rotate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/JOsee321/Rotex/internal/security"
)

// Request configures a rotation plan or execution.
type Request struct {
	Target          KeyTarget
	StoreTargets    []StoreScope
	SecretNames     []string
	ImmediateDelete bool
}

// EngineOption configures an Engine instance.
type EngineOption func(*Engine)

// WithClock overrides the clock used for timestamps and run IDs.
func WithClock(fn func() time.Time) EngineOption {
	return func(e *Engine) {
		if fn != nil {
			e.now = fn
		}
	}
}

// WithJournal overrides the local state journal directory.
func WithJournal(j *Journal) EngineOption {
	return func(e *Engine) {
		if j != nil {
			e.journal = j
		}
	}
}

// Engine executes the 6-stage in-place credential rotation state machine.
type Engine struct {
	provider CredentialProvider
	store    SecretStore
	journal  *Journal
	now      func() time.Time
}

// NewEngine constructs a rotation Engine backed by provider and store.
func NewEngine(provider CredentialProvider, store SecretStore, opts ...EngineOption) *Engine {
	e := &Engine{
		provider: provider,
		store:    store,
		journal:  NewJournal(""),
		now:      func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}
	return e
}

// Plan executes read-only preflight checks and returns a deterministic execution plan.
func (e *Engine) Plan(ctx context.Context, req Request) (*ExecutionPlan, error) {
	if err := e.validateRequest(req); err != nil {
		return nil, err
	}

	pre, err := e.provider.PreflightCheck(ctx, req.Target)
	if err != nil {
		return nil, err
	}

	var warnings []string
	for _, scope := range req.StoreTargets {
		if err := e.store.PreflightScope(ctx, scope); err != nil {
			return nil, fmt.Errorf("preflight secret store %s: %w", scope.Label(), err)
		}
	}

	secretNames := resolveSecretNames(req.SecretNames)
	if pre.ResolvedOldKeyID == "" {
		warnings = append(warnings, "no existing IAM access key found; rotation will mint a fresh key without deactivation")
	}

	return &ExecutionPlan{
		Provider:        e.provider.Name(),
		Target:          KeyTarget{IAMUser: req.Target.IAMUser, OldKeyID: pre.ResolvedOldKeyID},
		Preflight:       pre,
		SecretNames:     secretNames,
		StoreTargets:    slices.Clone(req.StoreTargets),
		ImmediateDelete: req.ImmediateDelete,
		Warnings:        warnings,
		GeneratedAt:     e.now().UTC(),
	}, nil
}

// Apply runs the 6-stage rotation state machine with automatic rollback on failure.
func (e *Engine) Apply(ctx context.Context, req Request) (*RunState, error) {
	if err := e.validateRequest(req); err != nil {
		return nil, err
	}

	now := e.now().UTC()
	runID, err := generateRunID(now)
	if err != nil {
		return nil, err
	}

	secretNames := resolveSecretNames(req.SecretNames)
	targets := make([]TargetInjectionStatus, len(req.StoreTargets))
	for i, sc := range req.StoreTargets {
		targets[i] = TargetInjectionStatus{Target: sc, Status: "PENDING"}
	}

	state := &RunState{
		RunID:           runID,
		Provider:        e.provider.Name(),
		Target:          req.Target,
		Stage:           StagePreflight,
		SecretNames:     secretNames,
		Targets:         targets,
		ImmediateDelete: req.ImmediateDelete,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// Stage 1: PREFLIGHT
	pre, err := e.provider.PreflightCheck(ctx, req.Target)
	if err != nil {
		state.Stage = StageFailedRecoverable
		state.Error = err.Error()
		_ = e.saveState(state)
		return state, err
	}
	state.OldKeyID = pre.ResolvedOldKeyID
	state.Target.OldKeyID = pre.ResolvedOldKeyID

	for _, scope := range req.StoreTargets {
		if err := e.store.PreflightScope(ctx, scope); err != nil {
			state.Stage = StageFailedRecoverable
			state.Error = err.Error()
			_ = e.saveState(state)
			return state, fmt.Errorf("preflight secret store %s: %w", scope.Label(), err)
		}
	}
	if err := e.saveState(state); err != nil {
		return state, err
	}

	// Stage 2: MINT (dual-key window; old key remains Active)
	state.Stage = StageMint
	mat, err := e.provider.MintKey(ctx, state.Target)
	if err != nil {
		state.Stage = StageFailedRecoverable
		state.Error = err.Error()
		_ = e.saveState(state)
		return state, err
	}
	defer mat.Wipe()

	state.NewKeyID = mat.KeyID
	if err := e.saveState(state); err != nil {
		return state, err
	}

	// Stage 3: INJECT (encrypted locally via sealed box)
	state.Stage = StageInject
	for i := range state.Targets {
		scope := state.Targets[i].Target
		if injErr := e.injectScope(ctx, scope, secretNames, mat); injErr != nil {
			state.Targets[i].Status = "FAILED"
			state.Targets[i].Error = injErr.Error()
			return e.autoRollback(ctx, state, fmt.Errorf("inject secrets into %s: %w", scope.Label(), injErr))
		}
		state.Targets[i].Status = "INJECTED"
		if err := e.saveState(state); err != nil {
			return e.autoRollback(ctx, state, err)
		}
	}

	// Stage 4: VERIFY (smoke test new credentials before touching old key)
	state.Stage = StageVerify
	if err := e.saveState(state); err != nil {
		return e.autoRollback(ctx, state, err)
	}
	if err := e.provider.VerifyKey(ctx, mat); err != nil {
		return e.autoRollback(ctx, state, err)
	}

	// Stage 5: DEACTIVATE old key (grace period for instant manual rollback)
	if state.OldKeyID != "" {
		state.Stage = StageDeactivate
		if err := e.provider.DeactivateKey(ctx, state.Target, state.OldKeyID); err != nil {
			state.Stage = StageFailedRecoverable
			state.Error = err.Error()
			_ = e.saveState(state)
			return state, err
		}
		state.OldDeactivated = true

		if req.ImmediateDelete {
			if err := e.provider.DeleteKey(ctx, state.Target, state.OldKeyID); err != nil {
				state.Stage = StageFailedRecoverable
				state.Error = err.Error()
				_ = e.saveState(state)
				return state, err
			}
			state.OldDeleted = true
			state.Stage = StageRevoked
			if err := e.saveState(state); err != nil {
				return state, err
			}
			return state, nil
		}
	}

	state.Stage = StageCompleted
	if err := e.saveState(state); err != nil {
		return state, err
	}
	return state, nil
}

// Rollback recovers a previously persisted rotation run by reactivating the old key
// (if deactivated) and deleting the newly minted key (if not yet deleted).
func (e *Engine) Rollback(ctx context.Context, runID string) (*RunState, error) {
	if e.provider == nil {
		return nil, errors.New("credential provider must not be nil")
	}
	state, err := e.journal.Load(runID)
	if err != nil {
		return nil, err
	}

	if state.OldDeactivated && !state.OldDeleted && state.OldKeyID != "" {
		if err := e.provider.ReactivateKey(ctx, state.Target, state.OldKeyID); err != nil {
			state.Stage = StageFailedRecoverable
			state.Error = fmt.Sprintf("rollback reactivate %s: %v", state.OldKeyID, err)
			_ = e.saveState(state)
			return state, err
		}
		state.OldDeactivated = false
	}

	if state.NewKeyID != "" && !state.NewDeleted {
		if err := e.provider.DeleteKey(ctx, state.Target, state.NewKeyID); err != nil {
			state.Stage = StageFailedRecoverable
			state.Error = fmt.Sprintf("rollback delete new key %s: %v", state.NewKeyID, err)
			_ = e.saveState(state)
			return state, err
		}
		state.NewDeleted = true
	}

	state.Stage = StageRolledBack
	if err := e.saveState(state); err != nil {
		return state, err
	}
	return state, nil
}

// Cleanup permanently deletes the deactivated old key after the grace period.
func (e *Engine) Cleanup(ctx context.Context, runID string) (*RunState, error) {
	if e.provider == nil {
		return nil, errors.New("credential provider must not be nil")
	}
	state, err := e.journal.Load(runID)
	if err != nil {
		return nil, err
	}
	if state.OldDeleted || state.OldKeyID == "" {
		state.Stage = StageRevoked
		_ = e.saveState(state)
		return state, nil
	}
	if state.Stage != StageCompleted && state.Stage != StageDeactivate {
		return nil, fmt.Errorf("run %s is in stage %s; only COMPLETED runs can be cleaned up", runID, state.Stage)
	}
	if err := e.provider.DeleteKey(ctx, state.Target, state.OldKeyID); err != nil {
		return state, err
	}
	state.OldDeleted = true
	state.Stage = StageRevoked
	if err := e.saveState(state); err != nil {
		return state, err
	}
	return state, nil
}

func (e *Engine) injectScope(ctx context.Context, scope StoreScope, secretNames []string, mat *SecretMaterial) error {
	for _, name := range secretNames {
		val, ok := mat.Values[name]
		if !ok || val == nil {
			return fmt.Errorf("provider did not mint secret material for %s", name)
		}
		if err := e.store.UpdateSecret(ctx, scope, name, val); err != nil {
			return security.SanitizeError(err, string(val.Expose()))
		}
	}
	return nil
}

func (e *Engine) autoRollback(ctx context.Context, state *RunState, cause error) (*RunState, error) {
	state.Stage = StageFailedRecoverable
	state.Error = cause.Error()
	_ = e.saveState(state)

	if state.NewKeyID != "" && !state.NewDeleted {
		if delErr := e.provider.DeleteKey(ctx, state.Target, state.NewKeyID); delErr != nil {
			state.Error = fmt.Sprintf("%v (automatic rollback failed deleting %s: %v)", cause, state.NewKeyID, delErr)
			_ = e.saveState(state)
			return state, fmt.Errorf("%w; rollback failed: %v", cause, delErr)
		}
		state.NewDeleted = true
		state.Stage = StageRolledBack
		_ = e.saveState(state)
	}
	return state, cause
}

func (e *Engine) validateRequest(req Request) error {
	if e.provider == nil {
		return errors.New("credential provider must not be nil")
	}
	if e.store == nil {
		return errors.New("secret store must not be nil")
	}
	if strings.TrimSpace(req.Target.IAMUser) == "" {
		return errors.New("IAM user is required")
	}
	if len(req.StoreTargets) == 0 {
		return errors.New("at least one target repository or environment is required")
	}
	return nil
}

func (e *Engine) saveState(state *RunState) error {
	state.UpdatedAt = e.now().UTC()
	return e.journal.Save(state)
}

func resolveSecretNames(names []string) []string {
	if len(names) == 0 {
		return []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}
	}
	var clean []string
	for _, n := range names {
		u := strings.ToUpper(strings.TrimSpace(n))
		if u != "" && !slices.Contains(clean, u) {
			clean = append(clean, u)
		}
	}
	sort.Strings(clean)
	return clean
}

func generateRunID(now time.Time) (string, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate run ID: %w", err)
	}
	return fmt.Sprintf("rot-%s-%s", now.UTC().Format("20060102-150405"), hex.EncodeToString(buf[:])), nil
}
