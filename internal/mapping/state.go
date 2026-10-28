package mapping

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/frederikb96/tandemvault/internal/vault"
)

// State is state.json: per mapping, the 1Password item version and the
// fingerprint of each vault entry's ciphertext at the last sync. It holds
// nothing derived from a plaintext value, so the file reveals nothing about
// the values even to someone who can read it.
type State struct {
	Version  int                      `json:"version"`
	Mappings map[string]*MappingState `json:"mappings"`
}

// MappingState is what the last sync saw for one mapping.
type MappingState struct {
	Item      string `json:"item"`
	OpVersion uint64 `json:"op_version"`
	// Vault maps entry names to the fingerprint they had after the last sync.
	// An entry that was absent is recorded as "".
	Vault map[string]string `json:"vault"`
}

const stateVersion = 1

// LoadState reads path. A missing file is an empty state.
func LoadState(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &State{Version: stateVersion, Mappings: map[string]*MappingState{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.Version != stateVersion {
		return nil, fmt.Errorf("%s: unsupported state version %d", path, s.Version)
	}
	if s.Mappings == nil {
		s.Mappings = map[string]*MappingState{}
	}
	return &s, nil
}

// Save writes the file atomically.
func (s *State) Save(path string) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return vault.WriteFileAtomic(path, append(raw, '\n'), 0o600)
}
