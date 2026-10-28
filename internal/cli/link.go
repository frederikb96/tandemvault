package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/frederikb96/tandemvault/internal/mapping"
	"github.com/frederikb96/tandemvault/internal/onepassword"
)

// multiFlag collects a repeatable flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// triBool is a flag that remembers whether it was given.
type triBool struct {
	set   bool
	value bool
}

func (t *triBool) String() string   { return fmt.Sprint(t.value) }
func (t *triBool) IsBoolFlag() bool { return true }
func (t *triBool) Set(v string) error {
	switch v {
	case "true", "1":
		t.value = true
	case "false", "0":
		t.value = false
	default:
		return fmt.Errorf("not a boolean: %s", v)
	}
	t.set = true
	return nil
}

func (a *App) cmdLink(args []string) (int, error) {
	fs := newFlagSet(a, "link", "link [flags] <title|item-id>   or   link --create [flags] <title>")
	vaultName := fs.String("vault", "", "vault holding the entries")
	prefix := fs.String("prefix", "", "entry name prefix, e.g. EXAMPLE gives EXAMPLE_USER, EXAMPLE_PASSWORD, ...")
	fields := fs.String("fields", "", "comma-separated fields to sync (username,password,otp,url; default all)")
	var names multiFlag
	fs.Var(&names, "name", "entry name for one field, field=NAME (repeatable)")
	var passkey triBool
	fs.Var(&passkey, "passkey", "the 1Password item holds a passkey (the cli backend then never edits it)")
	noPasskey := fs.Bool("no-passkey", false, "the 1Password item holds no passkey (lets the cli backend edit it)")
	opVault := fs.String("op-vault", "", "ID of the 1Password vault to search in or create the item in (tandemvault vaults lists them)")
	create := fs.Bool("create", false, "create the 1Password item from the vault entries")
	lease := fs.Bool("lease", false, "pull the item only for a while; give it back with tandemvault return")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError, err
	}
	if len(pos) != 1 {
		fs.Usage()
		return exitError, errors.New("link takes exactly one title or item ID")
	}
	if *prefix == "" {
		return exitError, errors.New("--prefix is required")
	}
	c, err := a.config()
	if err != nil {
		return exitError, err
	}
	vn, err := c.PickVault(*vaultName)
	if err != nil {
		return exitError, err
	}
	m := &mapping.Mapping{Vault: vn, Prefix: *prefix, OpVault: *opVault, Lease: *lease}
	if *lease && *create {
		return exitError, errors.New("--lease pulls an existing item; it does not go with --create")
	}
	switch {
	case *create:
		if passkey.set || *noPasskey {
			return exitError, errors.New("--create makes a new item, which has no passkey; drop --passkey/--no-passkey")
		}
		if *opVault == "" {
			return exitError, errors.New("--create needs --op-vault")
		}
		m.Create, m.Title = true, pos[0]
	default:
		if passkey.set && *noPasskey {
			return exitError, errors.New("--passkey and --no-passkey contradict each other")
		}
		if passkey.set || *noPasskey {
			pk := passkey.set && passkey.value
			m.Passkey = &pk
		}
		if onepassword.IsID(pos[0]) {
			m.Title = ""
			if *opVault != "" {
				m.Item = pos[0]
			} else {
				// The vault is found on the next sync.
				m.Title = pos[0]
			}
		} else {
			m.Title = pos[0]
		}
	}
	if *fields != "" {
		for _, f := range strings.Split(*fields, ",") {
			fl, err := onepassword.ParseField(strings.TrimSpace(f))
			if err != nil {
				return exitError, err
			}
			m.Fields = append(m.Fields, fl)
		}
	}
	for _, n := range names {
		field, name, ok := strings.Cut(n, "=")
		if !ok {
			return exitError, fmt.Errorf("--name %q: use field=NAME", n)
		}
		fl, err := onepassword.ParseField(field)
		if err != nil {
			return exitError, err
		}
		if m.Names == nil {
			m.Names = map[onepassword.Field]string{}
		}
		m.Names[fl] = name
	}
	mf, err := mapping.Load(c.Mappings)
	if err != nil {
		return exitError, err
	}
	mf.Mappings = append(mf.Mappings, m)
	if err := mf.Validate(c); err != nil {
		return exitError, err
	}
	if err := mf.Save(c.Mappings); err != nil {
		return exitError, err
	}
	fmt.Fprintf(a.Stdout, "Added %s (%s). The next tandemvault sync carries it out.\n", m.Key(), strings.Join(m.EntryNames(), ", "))
	return exitOK, nil
}

func (a *App) cmdUnlink(args []string) (int, error) {
	fs := newFlagSet(a, "unlink", "unlink --keep op|vault|both [--vault V] <PREFIX>")
	vaultName := fs.String("vault", "", "vault holding the entries, when the prefix exists in several")
	keep := fs.String("keep", "", "op: keep 1Password, vault copy to trash; vault: keep the vault, 1Password item to Recently Deleted; both: only stop syncing; none: retire, write back, then 1Password item to Recently Deleted and vault copy deleted")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError, err
	}
	if len(pos) != 1 {
		fs.Usage()
		return exitError, errors.New("unlink takes exactly one prefix")
	}
	c, err := a.config()
	if err != nil {
		return exitError, err
	}
	mf, err := mapping.Load(c.Mappings)
	if err != nil {
		return exitError, err
	}
	m, err := mf.Find(*vaultName, pos[0])
	if err != nil {
		return exitError, err
	}
	switch *keep {
	case "none":
		if !m.Resolved() {
			return exitError, fmt.Errorf("%s is not linked to a 1Password item yet; use --keep both to drop the mapping", m.Key())
		}
		m.Unlink = mapping.Retire
		fmt.Fprintf(a.Stdout, "Marked %s to retire on the next tandemvault sync.\n", m.Key())
	case mapping.KeepOnePassword, mapping.KeepVault:
		if m.Create {
			mf.Remove(m)
			fmt.Fprintf(a.Stdout, "Removed the pending create request %s.\n", m.Key())
		} else {
			m.Unlink = *keep
			fmt.Fprintf(a.Stdout, "Marked %s to break on the next tandemvault sync.\n", m.Key())
		}
	case "both":
		mf.Remove(m)
		st, err := mapping.LoadState(c.State)
		if err != nil {
			return exitError, err
		}
		delete(st.Mappings, m.Key())
		if err := st.Save(c.State); err != nil {
			return exitError, err
		}
		fmt.Fprintf(a.Stdout, "Removed %s; both sides keep their copy.\n", m.Key())
	default:
		return exitError, errors.New("--keep must be op, vault, both or none")
	}
	if err := mf.Save(c.Mappings); err != nil {
		return exitError, err
	}
	return exitOK, nil
}

func (a *App) cmdReturn(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet(a, "return", "return [--vault V] <PREFIX>...")
	vaultName := fs.String("vault", "", "vault holding the entries, when a prefix exists in several")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError, err
	}
	if len(pos) == 0 {
		fs.Usage()
		return exitError, errors.New("return takes one or more prefixes")
	}
	e, err := a.localEngine()
	if err != nil {
		return exitError, err
	}
	code := exitOK
	for _, prefix := range pos {
		m, err := e.Mappings.Find(*vaultName, prefix)
		if err != nil {
			return exitError, err
		}
		switch {
		case m.Create || !m.Resolved():
			e.Mappings.Remove(m)
			fmt.Fprintf(a.Stdout, "%s was never linked; dropped the mapping, vault entries untouched.\n", m.Key())
			continue
		}
		done, err := e.ReturnUnchanged(ctx, m)
		if err != nil {
			return exitError, err
		}
		if done {
			fmt.Fprintf(a.Stdout, "Returned %s: unchanged since the last sync, vault copy deleted.\n", m.Key())
			continue
		}
		m.Unlink = mapping.Return
		code = exitPending
		fmt.Fprintf(a.Stdout, "Marked %s to return: the next tandemvault sync writes the vault's changes back, checks 1Password holds them, then deletes the vault copy.\n", m.Key())
	}
	if err := e.Mappings.Save(e.Config.Mappings); err != nil {
		return exitError, err
	}
	return code, nil
}

func (a *App) cmdVaults(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet(a, "vaults", "vaults")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError, err
	}
	if len(pos) > 0 {
		return exitError, errors.New("vaults takes no arguments")
	}
	b, err := a.onePassword(ctx)
	if err != nil {
		return exitError, err
	}
	vaults, err := b.Vaults(ctx)
	if err != nil {
		return exitError, err
	}
	for _, v := range vaults {
		line := v.ID + "  " + v.Title
		if v.Type != "" {
			line += "  (" + v.Type + ")"
		}
		fmt.Fprintln(a.Stdout, line)
	}
	return exitOK, nil
}

var _ flag.Value = (*triBool)(nil)
