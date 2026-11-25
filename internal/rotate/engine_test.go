package rotate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/security"
)

type fakeProvider struct {
	preflightInfo *PreflightInfo
	preflightErr  error
	mintedID      string
	mintedSecret  string
	verifyErr     error
	deactivated   []string
	reactivated   []string
	deleted       []string
}

func (f *fakeProvider) Name() string { return "fake-aws" }

func (f *fakeProvider) PreflightCheck(_ context.Context, _ KeyTarget) (*PreflightInfo, error) {
	if f.preflightErr != nil {
		return nil, f.preflightErr
	}
	return f.preflightInfo, nil
}

func (f *fakeProvider) MintKey(_ context.Context, _ KeyTarget) (*SecretMaterial, error) {
	return &SecretMaterial{
		KeyID: f.mintedID,
		Values: map[string]*security.SensitiveBytes{
			"AWS_ACCESS_KEY_ID":     security.NewSensitiveBytes([]byte(f.mintedID)),
			"AWS_SECRET_ACCESS_KEY": security.NewSensitiveBytes([]byte(f.mintedSecret)),
		},
	}, nil
}

func (f *fakeProvider) VerifyKey(_ context.Context, _ *SecretMaterial) error {
	return f.verifyErr
}

func (f *fakeProvider) DeactivateKey(_ context.Context, _ KeyTarget, keyID string) error {
	f.deactivated = append(f.deactivated, keyID)
	return nil
}

func (f *fakeProvider) ReactivateKey(_ context.Context, _ KeyTarget, keyID string) error {
	f.reactivated = append(f.reactivated, keyID)
	return nil
}

func (f *fakeProvider) DeleteKey(_ context.Context, _ KeyTarget, keyID string) error {
	f.deleted = append(f.deleted, keyID)
	return nil
}

type fakeStore struct {
	failRepo string
	updated  []string
}

func (s *fakeStore) Name() string { return "fake-github" }

func (s *fakeStore) PreflightScope(_ context.Context, _ StoreScope) error { return nil }

func (s *fakeStore) UpdateSecret(_ context.Context, scope StoreScope, name string, _ *security.SensitiveBytes) error {
	if s.failRepo != "" && scope.Repo == s.failRepo {
		return errors.New("simulated network drop on " + scope.Repo)
	}
	s.updated = append(s.updated, scope.Label()+":"+name)
	return nil
}

func TestEngineApplyHappyPathAndCleanup(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	prov := &fakeProvider{
		preflightInfo: &PreflightInfo{ResolvedOldKeyID: "AKIA_OLD", ExistingKeyCount: 1},
		mintedID:      "AKIA_NEW",
		mintedSecret:  "topSecretValueNeverStoredToDisk",
	}
	store := &fakeStore{}

	eng := NewEngine(prov, store, WithJournal(NewJournal(stateDir)), WithClock(func() time.Time { return now }))
	req := Request{
		Target: KeyTarget{IAMUser: "ci-deployer"},
		StoreTargets: []StoreScope{
			{Scope: model.ScopeRepo, Repo: "acme/api"},
			{Scope: model.ScopeEnvironment, Repo: "acme/web", Environment: "prod"},
		},
	}

	plan, err := eng.Plan(context.Background(), req)
	if err != nil || plan.Target.OldKeyID != "AKIA_OLD" || len(prov.deactivated) != 0 {
		t.Fatalf("Plan unexpected: %+v, err=%v", plan, err)
	}

	state, err := eng.Apply(context.Background(), req)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if state.Stage != StageCompleted || !state.OldDeactivated || state.OldDeleted {
		t.Fatalf("unexpected final state: %+v", state)
	}
	if len(store.updated) != 4 {
		t.Fatalf("expected 4 secret updates (2 secrets x 2 targets), got %v", store.updated)
	}

	// Verify state journal NEVER stores the raw secret value.
	rawState, err := os.ReadFile(filepath.Join(stateDir, state.RunID+".json"))
	if err != nil {
		t.Fatalf("read state file failed: %v", err)
	}
	if strings.Contains(string(rawState), "topSecretValueNeverStoredToDisk") {
		t.Fatalf("state file leaked secret material!")
	}

	// Cleanup deletes old key.
	revoked, err := eng.Cleanup(context.Background(), state.RunID)
	if err != nil || revoked.Stage != StageRevoked || !revoked.OldDeleted {
		t.Fatalf("Cleanup unexpected: %+v, err=%v", revoked, err)
	}
}

func TestEngineAutomaticRollbackOnMidFlightFailure(t *testing.T) {
	stateDir := t.TempDir()
	prov := &fakeProvider{
		preflightInfo: &PreflightInfo{ResolvedOldKeyID: "AKIA_OLD", ExistingKeyCount: 1},
		mintedID:      "AKIA_NEW",
		mintedSecret:  "secret-xyz",
	}
	store := &fakeStore{failRepo: "acme/web"}

	eng := NewEngine(prov, store, WithJournal(NewJournal(stateDir)))
	state, err := eng.Apply(context.Background(), Request{
		Target: KeyTarget{IAMUser: "ci-deployer"},
		StoreTargets: []StoreScope{
			{Scope: model.ScopeRepo, Repo: "acme/api"},
			{Scope: model.ScopeRepo, Repo: "acme/web"},
		},
	})
	if err == nil {
		t.Fatalf("expected error on mid-flight injection failure")
	}
	if state.Stage != StageRolledBack || !state.NewDeleted {
		t.Fatalf("expected automatic rollback to ROLLED_BACK deleting new key, got %+v", state)
	}
	if len(prov.deactivated) != 0 {
		t.Fatalf("old key must NEVER be deactivated when injection fails")
	}
	if len(prov.deleted) != 1 || prov.deleted[0] != "AKIA_NEW" {
		t.Fatalf("expected minted key AKIA_NEW to be deleted during rollback, got %v", prov.deleted)
	}
}

func TestEngineManualRollbackAfterCompletedRun(t *testing.T) {
	stateDir := t.TempDir()
	prov := &fakeProvider{
		preflightInfo: &PreflightInfo{ResolvedOldKeyID: "AKIA_OLD", ExistingKeyCount: 1},
		mintedID:      "AKIA_NEW",
		mintedSecret:  "secret-xyz",
	}
	store := &fakeStore{}
	eng := NewEngine(prov, store, WithJournal(NewJournal(stateDir)))

	state, err := eng.Apply(context.Background(), Request{
		Target:       KeyTarget{IAMUser: "ci-deployer"},
		StoreTargets: []StoreScope{{Scope: model.ScopeRepo, Repo: "acme/api"}},
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	rolledBack, err := eng.Rollback(context.Background(), state.RunID)
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}
	if rolledBack.Stage != StageRolledBack || rolledBack.OldDeactivated || !rolledBack.NewDeleted {
		t.Fatalf("unexpected rolledBack state: %+v", rolledBack)
	}
	if len(prov.reactivated) != 1 || prov.reactivated[0] != "AKIA_OLD" {
		t.Fatalf("expected AKIA_OLD reactivated, got %v", prov.reactivated)
	}
}
