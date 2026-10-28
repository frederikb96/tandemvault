// Package vault implements the two vault formats tandemvault reads and writes.
//
//   - sops-dotenv: one dotenv file encrypted with sops. Names are in clear,
//     values are ENC[...] blobs. Anything holding the sops age key can read it,
//     which makes it the always-open vault.
//   - age-dir: one armored age file per name, encrypted to a public recipient.
//     The matching identity is itself sealed with a passphrase, so reading
//     needs that passphrase while adding a new entry needs nothing.
//
// Both formats can be listed and fingerprinted without any key: the
// fingerprint of an entry is the sha256 of its ciphertext, so a changed entry
// is visible without decrypting it.
package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"

	"github.com/frederikb96/tandemvault/internal/config"
)

// Entry describes one name in a vault without its value.
type Entry struct {
	Present bool
	// Fingerprint is the sha256 of the entry's ciphertext. Empty when absent.
	Fingerprint string
	// ModTime is when the entry last changed, as far as the format can tell.
	// For sops-dotenv it is the file's mtime, an upper bound for every entry.
	ModTime time.Time
}

// PassphraseFunc returns the passphrase that unseals an age-dir identity.
type PassphraseFunc func(ctx context.Context) (string, error)

// Vault is a configured vault.
type Vault interface {
	Name() string
	Type() string
	// Names lists the entries. Needs no key.
	Names() ([]string, error)
	// Entries fingerprints the given names. Needs no key.
	Entries(names []string) (map[string]Entry, error)
	// Read decrypts the given names. Absent names are left out of the result.
	Read(ctx context.Context, names []string) (map[string]string, error)
	// Write adds or replaces one entry.
	Write(ctx context.Context, name, value string) error
	// Trash moves entries out of the vault into its trash, stamped with a UTC time.
	Trash(ctx context.Context, names []string, stamp string) error
	// ConflictCopies lists file-sync conflict copies of the vault's files.
	ConflictCopies() ([]string, error)
	// Init creates an empty vault.
	Init(ctx context.Context, opts InitOptions) error
}

// InitOptions configure Init.
type InitOptions struct {
	// AgeRecipients encrypt a new sops-dotenv vault.
	AgeRecipients []string
}

var nameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidName checks an entry name: letters, digits and underscores, not starting with a digit.
func ValidName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid name %q: use letters, digits and underscores", name)
	}
	return nil
}

// Open returns the vault configured under name.
func Open(c *config.Config, name string, passphrase PassphraseFunc) (Vault, error) {
	v, ok := c.Vaults[name]
	if !ok {
		return nil, fmt.Errorf("no vault named %q", name)
	}
	switch v.Type {
	case config.TypeSopsDotenv:
		return &SopsDotenv{name: name, path: v.Path, ageKeyFile: v.AgeKeyFile}, nil
	case config.TypeAgeDir:
		return &AgeDir{name: name, dir: v.Dir, identityPath: v.Identity, recipientPath: v.Recipient, passphrase: passphrase}, nil
	}
	return nil, fmt.Errorf("vault %s: unknown type %q", name, v.Type)
}

func fingerprint(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
