package rotate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// Save writes state atomically using restrictive file permissions (0600).
func (j *Journal) Save(state *RunState) error {
	if state == nil || strings.TrimSpace(state.RunID) == "" {
		return errors.New("run state and run_id are required")
	}
	if err := validateRunID(state.RunID); err != nil {
		return err
	}
	if err := os.MkdirAll(j.dir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
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
	data, err := os.ReadFile(j.pathFor(runID))
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
	if runID == "" || strings.ContainsAny(runID, `/\..`) {
		if strings.Contains(runID, "..") || strings.ContainsAny(runID, `/\`) {
			return fmt.Errorf("invalid run_id %q", runID)
		}
	}
	if runID == "" {
		return errors.New("run_id must not be empty")
	}
	return nil
}
