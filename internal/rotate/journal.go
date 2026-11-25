package rotate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var (
	runIDRe          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	inProcessLocksMu sync.Mutex
	inProcessLocks   = make(map[string]*sync.Mutex)
)

// Journal persists non-secret RunState metadata to .rotex/state/<run-id>.json.
type Journal struct {
	dir string
}

// NewJournal constructs a state journal rooted at dir (default ".rotex/state").
func NewJournal(dir string) *Journal {
	if strings.TrimSpace(dir) == "" {
		dir = filepath.Join(".rotex", "state")
	}
	return &Journal{dir: dir}
}

func (j *Journal) ensureSafeDir() error {
	if info, err := os.Lstat(j.dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("state directory %q must not be a symlink", j.dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("state path %q is not a directory", j.dir)
		}
	}
	if err := os.MkdirAll(j.dir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(j.dir, 0o700); err != nil {
		return fmt.Errorf("chmod state directory: %w", err)
	}
	return nil
}

// AcquireLock acquires a non-blocking exclusive advisory lock scoped to lockKey
// to prevent concurrent rotation runs from racing on IAM quotas or GitHub secrets.
func (j *Journal) AcquireLock(lockKey string) (func(), error) {
	if err := j.ensureSafeDir(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(lockKey)))
	lockPath := filepath.Join(j.dir, ".rotex-"+hex.EncodeToString(sum[:8])+".lock")
	absLockPath, err := filepath.Abs(lockPath)
	if err != nil {
		absLockPath = lockPath
	}

	inProcessLocksMu.Lock()
	mu, ok := inProcessLocks[absLockPath]
	if !ok {
		mu = &sync.Mutex{}
		inProcessLocks[absLockPath] = mu
	}
	inProcessLocksMu.Unlock()

	if !mu.TryLock() {
		return nil, fmt.Errorf("another rotation operation for %q is already in progress", lockKey)
	}

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		mu.Unlock()
		return nil, fmt.Errorf("open rotation lock file: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		mu.Unlock()
		return nil, fmt.Errorf("chmod rotation lock file: %w", err)
	}
	if err := tryLockFile(f); err != nil {
		_ = f.Close()
		mu.Unlock()
		return nil, fmt.Errorf("acquire rotation lock for %q: %w", lockKey, err)
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			unlockFile(f)
			_ = f.Close()
			mu.Unlock()
		})
	}, nil
}

// Save writes state atomically using restrictive file permissions (0600).
func (j *Journal) Save(state *RunState) error {
	if state == nil || strings.TrimSpace(state.RunID) == "" {
		return errors.New("run state and run_id are required")
	}
	if err := validateRunID(state.RunID); err != nil {
		return err
	}
	if err := j.ensureSafeDir(); err != nil {
		return err
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal run state: %w", err)
	}

	target := j.pathFor(state.RunID)
	tmpFile, err := os.CreateTemp(j.dir, state.RunID+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp state file: %w", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp state file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp state file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp state file: %w", err)
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return fmt.Errorf("commit state file: %w", err)
	}
	cleanupTmp = false
	return nil
}

// Load reads a previously saved RunState by runID.
func (j *Journal) Load(runID string) (*RunState, error) {
	if err := validateRunID(runID); err != nil {
		return nil, err
	}
	target := j.pathFor(runID)
	info, err := os.Lstat(target)
	if err != nil {
		return nil, fmt.Errorf("read run state %s: %w", runID, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to read run state %s through symlink", runID)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return nil, fmt.Errorf("read run state %s: %w", runID, err)
	}
	var state RunState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode run state %s: %w", runID, err)
	}
	return &state, nil
}

func (j *Journal) pathFor(runID string) string {
	return filepath.Join(j.dir, runID+".json")
}

func validateRunID(runID string) error {
	if runID == "" {
		return errors.New("run_id must not be empty")
	}
	if !runIDRe.MatchString(runID) {
		return fmt.Errorf("invalid run_id %q", runID)
	}
	return nil
}
