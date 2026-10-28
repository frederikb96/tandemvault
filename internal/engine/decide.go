// Package engine plans and applies a sync between 1Password and the vaults.
//
// Planning reads both sides and decides, per field, which way a value moves.
// Applying re-checks that nothing changed since the plan (compare-and-swap),
// writes 1Password first so its item history holds every value that gets
// replaced, then writes the vault, then records the new state.
package engine

import (
	"strings"
	"time"

	"github.com/frederikb96/tandemvault/internal/onepassword"
	"github.com/frederikb96/tandemvault/internal/otp"
)

// direction says which way a field moves.
type direction int

const (
	none direction = iota
	toVault
	toOnePassword
	// conflictOnePasswordWins: both sides changed and 1Password's change is
	// newer. The vault's value is written to 1Password first and 1Password's
	// value back on top, so both end up in the item's history.
	conflictOnePasswordWins
)

// side is one side's view of a field.
type side struct {
	value   string
	present bool
	// moved reports a change since the last sync. With no recorded sync it is true.
	moved bool
	time  time.Time
}

type decision struct {
	dir    direction
	reason string
}

// equalValues compares two values of a field. OTP secrets compare by their
// canonical form; an absent value equals an empty one.
func equalValues(f onepassword.Field, a, b string) bool {
	if f == onepassword.OTP && a != "" && b != "" {
		return otp.Equal(a, b)
	}
	if f == onepassword.URL {
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	return a == b
}

// decide picks the direction for one field. An absent or empty value never
// replaces a present one: it is filled from the other side. Removing a value
// is what unlink is for.
func decide(f onepassword.Field, op, v side, firstSync bool) decision {
	opVal, vVal := op.value, v.value
	if !op.present {
		opVal = ""
	}
	if !v.present {
		vVal = ""
	}
	switch {
	case equalValues(f, opVal, vVal):
		return decision{dir: none}
	case opVal == "":
		return decision{toOnePassword, "empty in 1Password"}
	case vVal == "":
		return decision{toVault, "missing in vault"}
	case firstSync:
		if v.time.After(op.time) {
			return decision{toOnePassword, "differs at first sync, vault newer"}
		}
		return decision{conflictOnePasswordWins, "differs at first sync, 1Password newer"}
	case v.moved && !op.moved:
		return decision{toOnePassword, "vault changed"}
	case op.moved && !v.moved:
		return decision{toVault, "1Password changed"}
	case v.time.After(op.time):
		return decision{toOnePassword, "both changed, vault newer"}
	default:
		return decision{conflictOnePasswordWins, "both changed, 1Password newer"}
	}
}
