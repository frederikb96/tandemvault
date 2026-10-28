package engine

import (
	"fmt"

	"github.com/frederikb96/tandemvault/internal/mapping"
)

// LocalStatus lists what the next sync has to do as far as can be told
// without 1Password and without any key: pending requests in mappings.yaml,
// vault entries whose ciphertext changed since the last sync, and conflict
// copies. Changes made in 1Password are not visible here.
func (e *Engine) LocalStatus() ([]string, error) {
	if err := e.Mappings.Validate(e.Config); err != nil {
		return nil, err
	}
	var out []string
	blockers, err := e.Blockers()
	if err != nil {
		return nil, err
	}
	for _, b := range blockers {
		out = append(out, "conflict copy, resolve it before syncing: "+b)
	}
	for _, m := range e.Mappings.Mappings {
		key := m.Key()
		switch {
		case m.Unlink == mapping.KeepVault:
			out = append(out, key+": break sync requested, keep vault")
			continue
		case m.Unlink == mapping.KeepOnePassword:
			out = append(out, key+": break sync requested, keep 1Password")
			continue
		case m.Unlink == mapping.Return:
			out = append(out, key+": return requested (write back, then delete the vault copy)")
			continue
		case m.Unlink == mapping.Retire:
			out = append(out, key+": retire requested (write back, delete the vault copy, 1Password item to Recently Deleted)")
			continue
		case m.Create:
			out = append(out, fmt.Sprintf("%s: create 1Password item %q requested", key, m.Title))
			continue
		case !m.Resolved():
			out = append(out, fmt.Sprintf("%s: link to %q pending", key, m.Title))
			continue
		}
		st := e.State.Mappings[key]
		if st == nil || st.Item != m.Item {
			out = append(out, key+": first sync pending")
			continue
		}
		entries, err := e.Vaults[m.Vault].Entries(m.EntryNames())
		if err != nil {
			return nil, err
		}
		for _, n := range m.EntryNames() {
			prev, ok := st.Vault[n]
			if !ok || prev != entries[n].Fingerprint {
				out = append(out, fmt.Sprintf("%s: %s changed in the vault", key, n))
			}
		}
	}
	return out, nil
}

// Leases lists the lease mappings not yet asked to return.
func (e *Engine) Leases() []string {
	var out []string
	for _, m := range e.Mappings.Mappings {
		if m.Lease && m.Unlink == "" {
			out = append(out, m.Key())
		}
	}
	return out
}
