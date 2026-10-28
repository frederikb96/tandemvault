// Package mapping reads and writes mappings.yaml, the list of 1Password
// items kept in step with vault entries, and state.json, what the last sync
// saw on each side.
//
// mappings.yaml holds names, IDs and directions only, so anything may edit
// it without a key: linking an item, asking for a new 1Password item, or
// breaking a sync are all edits to this file that the next sync carries out.
package mapping

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/frederikb96/tandemvault/internal/config"
	"github.com/frederikb96/tandemvault/internal/onepassword"
	"github.com/frederikb96/tandemvault/internal/vault"
)

// Keep values for Unlink: the side that keeps the entry.
const (
	KeepOnePassword = "op"
	KeepVault       = "vault"
)

// Mapping links one 1Password item to a group of vault entries.
type Mapping struct {
	// Vault is the configured vault holding the entries.
	Vault string `yaml:"vault"`
	// Prefix names the entries: <PREFIX>_USER, <PREFIX>_PASSWORD, ...
	Prefix string `yaml:"prefix"`
	// Item is the 1Password item ID. Empty until the item is found or created.
	Item string `yaml:"item,omitempty"`
	// OpVault is the ID of the 1Password vault holding the item, the vault to
	// search in, or the vault to create the item in. Never a title.
	OpVault string `yaml:"op_vault,omitempty"`
	// Title is what an unresolved mapping searches for, or the title of an
	// item to create.
	Title string `yaml:"title,omitempty"`
	// Fields limits the synced fields. Empty means all four.
	Fields []onepassword.Field `yaml:"fields,omitempty"`
	// Names overrides entry names per field.
	Names map[onepassword.Field]string `yaml:"names,omitempty"`
	// Passkey says whether the 1Password item holds a passkey. Only the CLI
	// backend cares: its whole-item edits replace passkeys, so it writes an
	// item only when this is explicitly false. Unset means unknown.
	Passkey *bool `yaml:"passkey,omitempty"`
	// Create asks the next sync to create the 1Password item from the vault entries.
	Create bool `yaml:"create,omitempty"`
	// Unlink asks the next sync to end this mapping, keeping the entry on
	// one side ("op" or "vault") and moving the other side's copy to its trash.
	Unlink string `yaml:"unlink,omitempty"`
}

// File is mappings.yaml.
type File struct {
	Mappings []*Mapping `yaml:"mappings"`
}

var prefixRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

var defaultSuffix = map[onepassword.Field]string{
	onepassword.Username: "_USER",
	onepassword.Password: "_PASSWORD",
	onepassword.OTP:      "_TOTP_SECRET",
	onepassword.URL:      "_URL",
}

// Key identifies a mapping: vault/PREFIX.
func (m *Mapping) Key() string { return m.Vault + "/" + m.Prefix }

// SyncedFields returns the fields this mapping syncs, in display order.
func (m *Mapping) SyncedFields() []onepassword.Field {
	if len(m.Fields) == 0 {
		return onepassword.AllFields
	}
	var out []onepassword.Field
	for _, f := range onepassword.AllFields {
		if slices.Contains(m.Fields, f) {
			out = append(out, f)
		}
	}
	return out
}

// NameFor returns the vault entry name for a field.
func (m *Mapping) NameFor(f onepassword.Field) string {
	if n, ok := m.Names[f]; ok {
		return n
	}
	return m.Prefix + defaultSuffix[f]
}

// EntryNames returns the entry names of all synced fields.
func (m *Mapping) EntryNames() []string {
	var out []string
	for _, f := range m.SyncedFields() {
		out = append(out, m.NameFor(f))
	}
	return out
}

// WithoutPasskey reports whether the mapping states that the item holds no passkey.
func (m *Mapping) WithoutPasskey() bool { return m.Passkey != nil && !*m.Passkey }

// Resolved reports whether the mapping points at a 1Password item.
func (m *Mapping) Resolved() bool { return m.Item != "" }

// Load reads path. A missing file is an empty list.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &File{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}

const header = "# tandemvault mappings. Edited by `tandemvault link` and `unlink`, carried out by `tandemvault sync`.\n"

// Save writes the file atomically.
func (f *File) Save(path string) error {
	var buf bytes.Buffer
	buf.WriteString(header)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(f); err != nil {
		return err
	}
	return vault.WriteFileAtomic(path, buf.Bytes(), 0o600)
}

// Find returns the mapping with the given prefix, in vaultName if set.
func (f *File) Find(vaultName, prefix string) (*Mapping, error) {
	var found []*Mapping
	for _, m := range f.Mappings {
		if m.Prefix == prefix && (vaultName == "" || m.Vault == vaultName) {
			found = append(found, m)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return nil, fmt.Errorf("no mapping with prefix %s", prefix)
	}
	return nil, fmt.Errorf("prefix %s is mapped in several vaults, name one with --vault", prefix)
}

// Remove drops a mapping.
func (f *File) Remove(m *Mapping) {
	f.Mappings = slices.DeleteFunc(f.Mappings, func(x *Mapping) bool { return x == m })
}

// Validate checks every mapping against the configuration and against each other.
func (f *File) Validate(c *config.Config) error {
	var errs []string
	keys := map[string]bool{}
	names := map[string]string{}
	items := map[string]string{}
	for i, m := range f.Mappings {
		where := fmt.Sprintf("mapping %d (%s)", i+1, m.Key())
		bad := func(format string, a ...any) { errs = append(errs, where+": "+fmt.Sprintf(format, a...)) }
		if _, ok := c.Vaults[m.Vault]; !ok {
			bad("vault %q is not configured", m.Vault)
		}
		if !prefixRE.MatchString(m.Prefix) {
			bad("prefix must be uppercase letters, digits and underscores")
		}
		if keys[m.Key()] {
			bad("defined twice")
		}
		keys[m.Key()] = true
		seen := map[onepassword.Field]bool{}
		for _, fl := range m.Fields {
			if _, err := onepassword.ParseField(string(fl)); err != nil {
				bad("%v", err)
			}
			if seen[fl] {
				bad("field %s listed twice", fl)
			}
			seen[fl] = true
		}
		for fl, n := range m.Names {
			if _, err := onepassword.ParseField(string(fl)); err != nil {
				bad("names: %v", err)
			}
			if err := vault.ValidName(n); err != nil {
				bad("names: %v", err)
			}
		}
		for _, n := range m.EntryNames() {
			k := m.Vault + "/" + n
			if other, ok := names[k]; ok {
				bad("entry %s is also used by %s", n, other)
			}
			names[k] = m.Key()
		}
		switch {
		case m.Create && m.Item != "":
			bad("create is set but the item already exists")
		case m.Create && (m.Title == "" || m.OpVault == ""):
			bad("create needs title and op_vault")
		case !m.Create && m.Item == "" && m.Title == "":
			bad("needs an item ID or a title to look up")
		case m.Item != "" && !onepassword.IsID(m.Item):
			bad("item %q is not a 1Password item ID", m.Item)
		case m.Item != "" && m.OpVault == "":
			bad("op_vault is required once the item is known")
		}
		switch m.Unlink {
		case "", KeepOnePassword, KeepVault:
		default:
			bad("unlink must be %q or %q", KeepOnePassword, KeepVault)
		}
		if m.OpVault != "" && !onepassword.IsID(m.OpVault) {
			bad("op_vault %q is not a 1Password vault ID (tandemvault vaults lists them)", m.OpVault)
		}
		if m.Unlink != "" && m.Create {
			bad("unlink and create are both set")
		}
		if m.Item != "" {
			if other, ok := items[m.Item]; ok {
				bad("1Password item %s is also mapped by %s", m.Item, other)
			}
			items[m.Item] = m.Key()
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}
