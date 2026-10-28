// Package onepassword reaches 1Password for the four fields tandemvault
// syncs: username, password, one-time password and the primary URL.
//
// Two backends exist. The SDK backend talks to the 1Password desktop app
// through its SDK integration and edits items as structs, field by field. The
// CLI backend runs the op command and edits an item by sending back the
// complete item as a JSON template; 1Password documents that this replaces
// passkeys, so the CLI backend only edits items mapped as having none.
//
// Every update re-reads the item and refuses to write when its version moved,
// so a change made between planning and applying is never overwritten.
package onepassword

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Field is one of the synced fields.
type Field string

const (
	Username Field = "username"
	Password Field = "password"
	OTP      Field = "otp"
	URL      Field = "url"
)

// AllFields lists the synced fields in display order.
var AllFields = []Field{Username, Password, OTP, URL}

// ParseField validates a field name.
func ParseField(s string) (Field, error) {
	for _, f := range AllFields {
		if string(f) == s {
			return f, nil
		}
	}
	return "", fmt.Errorf("unknown field %q (username, password, otp, url)", s)
}

// Item is the synced view of a 1Password item.
type Item struct {
	ID        string
	VaultID   string
	Title     string
	Version   uint64
	UpdatedAt time.Time
	// Values holds the synced fields that have a non-empty value.
	Values map[Field]string
	// OTPFields is the number of one-time password fields. Only an item with
	// at most one takes part in OTP sync.
	OTPFields int
}

// VaultInfo describes a 1Password vault.
type VaultInfo struct {
	ID    string
	Title string
	// Type is the SDK's vault type (personal, everyone, transfer, userCreated, ...); empty for the CLI backend.
	Type string
}

// Candidate is an item matching a lookup.
type Candidate struct {
	ID         string
	VaultID    string
	VaultTitle string
	Title      string
}

// ErrVersionMismatch means the item changed since it was read.
var ErrVersionMismatch = errors.New("the 1Password item changed since it was read")

// Backend is a way of reaching 1Password.
type Backend interface {
	// Kind is "sdk" or "cli".
	Kind() string
	Get(ctx context.Context, vaultID, itemID string) (Item, error)
	// Vaults lists the vaults the account can see.
	Vaults(ctx context.Context) ([]VaultInfo, error)
	// Find looks an item up by ID or exact title, optionally inside one vault
	// (by ID). Title matching falls back to case-insensitive when no exact
	// match exists.
	Find(ctx context.Context, query, vault string) ([]Candidate, error)
	// Update writes the given fields and nothing else. It fails with
	// ErrVersionMismatch when the item's version is not expectVersion.
	Update(ctx context.Context, vaultID, itemID string, expectVersion uint64, set map[Field]string) (Item, error)
	// Create adds a Login item to the vault with the given ID.
	Create(ctx context.Context, vault, title string, values map[Field]string) (Item, error)
	// Delete moves an item to Recently Deleted.
	Delete(ctx context.Context, vaultID, itemID string) error
	// Resolve reads an op:// secret reference.
	Resolve(ctx context.Context, ref string) (string, error)
}

// IsID reports whether s looks like a 1Password item or vault ID (26
// lowercase letters and digits).
func IsID(s string) bool {
	if len(s) != 26 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
