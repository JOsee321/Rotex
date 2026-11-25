package rotate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
	failRepo        string
	failOnSecretNum int
	putCount        int
	updated         []string
}

func (s *fakeStore) Name() string { return "fake-github" }

func (s *fakeStore) PreflightScope(_ context.Context, _ StoreScope) error { return nil }

func (s *fakeStore) UpdateSecret(_ context.Context, scope StoreScope, name string, val *security.SensitiveBytes) error {
	s.putCount++
	if s.failOnSecretNum > 0 && s.putCount == s.failOnSecretNum {
		return errors.New("simulated failure leaking " + string(val.Expose()))
	}
	if s.failRepo != "" && scope.Repo == s.failRepo {
		return errors.New("simulated network drop on " + scope.Repo + " with " + string(val.Expose()))
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

func TestEngineAutomaticRollbackOnVerifyAndFirstSecretFailure(t *testing.T) {
	stateDir := t.TempDir()
	prov := &fakeProvider{
		preflightInfo: &PreflightInfo{ResolvedOldKeyID: "AKIA_OLD", ExistingKeyCount: 1},
		mintedID:      "AKIA_NEW",
		mintedSecret:  "secret-xyz",
		verifyErr:     errors.New("STS verification failed"),
	}
	store := &fakeStore{}

	eng := NewEngine(prov, store, WithJournal(NewJournal(stateDir)))
	state, err := eng.Apply(context.Background(), Request{
		Target: KeyTarget{IAMUser: "ci-deployer"},
		StoreTargets: []StoreScope{
			{Scope: model.ScopeRepo, Repo: "acme/api"},
			{Scope: model.ScopeRepo, Repo: "acme/web"},
		},
	})
	if err == nil {
		t.Fatalf("expected error on verify failure")
	}
	if len(store.updated) != 0 {
		t.Fatalf("VerifyKey failure must abort BEFORE modifying any GitHub secrets, got %v", store.updated)
	}
	if state.Stage != StageRolledBack || !state.NewDeleted {
		t.Fatalf("expected automatic rollback to ROLLED_BACK deleting new key, got %+v", state)
	}
	if len(prov.deactivated) != 0 {
		t.Fatalf("old key must NEVER be deactivated when verification fails")
	}
	if len(prov.deleted) != 1 || prov.deleted[0] != "AKIA_NEW" {
		t.Fatalf("expected minted key AKIA_NEW to be deleted during rollback, got %v", prov.deleted)
	}

	// Failure on the very first secret write (zero mutations) also deletes AKIA_NEW safely.
	prov2 := &fakeProvider{
		preflightInfo: &PreflightInfo{ResolvedOldKeyID: "AKIA_OLD", ExistingKeyCount: 1},
		mintedID:      "AKIA_NEW_2",
		mintedSecret:  "secret-xyz-2",
	}
	store2 := &fakeStore{failOnSecretNum: 1}
	eng2 := NewEngine(prov2, store2, WithJournal(NewJournal(stateDir)))
	state2, err := eng2.Apply(context.Background(), Request{
		Target:       KeyTarget{IAMUser: "ci-deployer"},
		StoreTargets: []StoreScope{{Scope: model.ScopeRepo, Repo: "acme/api"}},
	})
	if err == nil || state2.Stage != StageRolledBack || !state2.NewDeleted {
		t.Fatalf("expected pre-mutation injection failure to rollback cleanly, got state=%+v err=%v", state2, err)
	}
	if strings.Contains(state2.Error, "secret-xyz-2") || strings.Contains(err.Error(), "secret-xyz-2") {
		t.Fatalf("error/journal leaked raw secret!")
	}
}

func TestEnginePartialInjectionPreservesBothActiveKeys(t *testing.T) {
	stateDir := t.TempDir()
	prov := &fakeProvider{
		preflightInfo: &PreflightInfo{ResolvedOldKeyID: "AKIA_OLD", ExistingKeyCount: 1},
		mintedID:      "AKIA_NEW",
		mintedSecret:  "secret-never-journaled",
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
		t.Fatalf("expected error on partial injection failure")
	}
	if state.Stage != StageFailedRecoverable || state.NewDeleted || state.OldDeactivated {
		t.Fatalf("partial injection must keep both old and new keys active in FAILED_RECOVERABLE, got %+v", state)
	}
	if len(prov.deactivated) != 0 || len(prov.deleted) != 0 {
		t.Fatalf("neither old nor new key may be deactivated/deleted after partial GitHub write; deactivated=%v deleted=%v", prov.deactivated, prov.deleted)
	}
	rawState, readErr := os.ReadFile(filepath.Join(stateDir, state.RunID+".json"))
	if readErr != nil || strings.Contains(string(rawState), "secret-never-journaled") {
		t.Fatalf("journal missing or leaked secret: readErr=%v", readErr)
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

func TestEngineCrashRecoveryRollbackAndRevokedGuard(t *testing.T) {
	stateDir := t.TempDir()
	j := NewJournal(stateDir)
	prov := &fakeProvider{}
	eng := NewEngine(prov, &fakeStore{}, WithJournal(j))

	// Simulate crash right after DeactivateKey executed (StageDeactivate persisted via WAL, OldDeactivated still false on disk).
	crashState := &RunState{
		RunID:          "rot-crash-deactivate",
		Provider:       "fake-aws",
		Target:         KeyTarget{IAMUser: "ci-deployer", OldKeyID: "AKIA_OLD"},
		OldKeyID:       "AKIA_OLD",
		NewKeyID:       "AKIA_NEW",
		Stage:          StageDeactivate,
		OldDeactivated: false,
	}
	if err := j.Save(crashState); err != nil {
		t.Fatalf("Save crashState failed: %v", err)
	}

	recovered, err := eng.Rollback(context.Background(), "rot-crash-deactivate")
	if err != nil {
		t.Fatalf("crash recovery Rollback failed: %v", err)
	}
	if recovered.Stage != StageRolledBack || recovered.OldDeactivated || !recovered.NewDeleted {
		t.Fatalf("unexpected recovered state: %+v", recovered)
	}
	if len(prov.reactivated) != 1 || prov.reactivated[0] != "AKIA_OLD" {
		t.Fatalf("expected crash recovery to reactivate AKIA_OLD, got %v", prov.reactivated)
	}

	// Rollback must refuse when old key was already deleted (preventing zero-key outage).
	revokedState := &RunState{
		RunID:      "rot-already-revoked",
		Provider:   "fake-aws",
		Target:     KeyTarget{IAMUser: "ci-deployer", OldKeyID: "AKIA_OLD"},
		OldKeyID:   "AKIA_OLD",
		NewKeyID:   "AKIA_NEW",
		Stage:      StageRevoked,
		OldDeleted: true,
	}
	if err := j.Save(revokedState); err != nil {
		t.Fatalf("Save revokedState failed: %v", err)
	}
	if _, err := eng.Rollback(context.Background(), "rot-already-revoked"); err == nil {
		t.Fatalf("expected Rollback on REVOKED run to be rejected")
	}
	if len(prov.deleted) != 1 { // Only AKIA_NEW from crashState above, never from revokedState
		t.Fatalf("Rollback must NOT delete NewKeyID after OldDeleted=true, deleted=%v", prov.deleted)
	}

	// Cleanup must reject non-completed runs even when OldKeyID is empty.
	failedNoOld := &RunState{
		RunID:    "rot-failed-no-old",
		Provider: "fake-aws",
		Target:   KeyTarget{IAMUser: "ci-deployer"},
		Stage:    StageRolledBack,
	}
	if err := j.Save(failedNoOld); err != nil {
		t.Fatalf("Save failedNoOld failed: %v", err)
	}
	if _, err := eng.Cleanup(context.Background(), "rot-failed-no-old"); err == nil {
		t.Fatalf("expected Cleanup on ROLLED_BACK run to fail")
	}
}

func TestJournalSecurityRunIDPermissionsAndLocking(t *testing.T) {
	stateDir := t.TempDir()
	j := NewJournal(stateDir)

	for _, badID := range []string{"", ".", "..", "../evil", `a\b`, "rot:1", "rot 1"} {
		if _, err := j.Load(badID); err == nil {
			t.Fatalf("expected invalid run_id %q to be rejected", badID)
		}
	}

	state := &RunState{
		RunID:    "rot-20261125-120000-deadbeef",
		Provider: "aws-iam",
		Target:   KeyTarget{IAMUser: "ci"},
		Stage:    StageCompleted,
	}
	if err := j.Save(state); err != nil {
		t.Fatalf("Journal.Save failed: %v", err)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(stateDir, state.RunID+".json"))
		if err != nil {
			t.Fatalf("stat failed: %v", err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("expected 0600 permissions on state file, got %o", mode)
		}
	}

	// Concurrent lock acquisition on same target must fail fast.
	release, err := j.AcquireLock("aws-iam:ci")
	if err != nil {
		t.Fatalf("AcquireLock failed: %v", err)
	}
	if _, err := j.AcquireLock("aws-iam:ci"); err == nil {
		t.Fatalf("expected second concurrent AcquireLock to fail")
	}
	release()

	release2, err := j.AcquireLock("aws-iam:ci")
	if err != nil {
		t.Fatalf("expected AcquireLock after release to succeed, got %v", err)
	}
	release2()
}
