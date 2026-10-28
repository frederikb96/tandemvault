package cli

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/frederikb96/tandemvault/internal/config"
	"github.com/frederikb96/tandemvault/internal/redact"
	"github.com/frederikb96/tandemvault/internal/vault"
)

func (a *App) cmdVault(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		return exitError, errors.New("vault needs a subcommand: init, names, get, set, unset, run")
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "init":
		return a.vaultInit(ctx, args)
	case "names":
		return a.vaultNames(args)
	case "get":
		return a.vaultGet(ctx, args)
	case "set":
		return a.vaultSet(ctx, args)
	case "verify":
		return a.vaultVerify(ctx, args)
	case "unset":
		return a.vaultUnset(ctx, args)
	case "run":
		return a.vaultRun(ctx, args)
	}
	return exitError, fmt.Errorf("unknown vault subcommand %q", sub)
}

func (a *App) pickVault(name string, confirmPassphrase bool) (vault.Vault, error) {
	c, err := a.config()
	if err != nil {
		return nil, err
	}
	vn, err := c.PickVault(name)
	if err != nil {
		return nil, err
	}
	return a.openVault(vn, confirmPassphrase)
}

func (a *App) vaultInit(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet(a, "vault init", "vault init [--vault V] [--age-recipient R]...")
	vaultName := fs.String("vault", "", "vault to create")
	var recipients multiFlag
	fs.Var(&recipients, "age-recipient", "age recipient for a sops-dotenv vault (repeatable; default: the recipients of the sops age key)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError, err
	}
	if len(pos) > 0 {
		return exitError, errors.New("vault init takes no arguments")
	}
	v, err := a.pickVault(*vaultName, true)
	if err != nil {
		return exitError, err
	}
	opts := vault.InitOptions{AgeRecipients: recipients}
	if v.Type() == config.TypeSopsDotenv && len(opts.AgeRecipients) == 0 {
		c, _ := a.config()
		if opts.AgeRecipients, err = recipientsFromKeyFile(c.Vaults[v.Name()].AgeKeyFile); err != nil {
			return exitError, err
		}
	}
	if err := v.Init(ctx, opts); err != nil {
		return exitError, err
	}
	fmt.Fprintf(a.Stdout, "Created vault %s.\n", v.Name())
	return exitOK, nil
}

// recipientsFromKeyFile derives the public recipients of the sops age key:
// the configured age_key_file, else $SOPS_AGE_KEY_FILE, else sops' default
// location.
func recipientsFromKeyFile(path string) ([]string, error) {
	if path == "" {
		path = os.Getenv("SOPS_AGE_KEY_FILE")
	}
	if path == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(dir, "sops", "age", "keys.txt")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("no --age-recipient given and no age key at %s", path)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("%s holds no age identity", path)
	}
	var out []string
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			out = append(out, x.Recipient().String())
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s holds no X25519 age identity, pass --age-recipient", path)
	}
	return out, nil
}

func (a *App) vaultNames(args []string) (int, error) {
	fs := newFlagSet(a, "vault names", "vault names [--vault V]")
	vaultName := fs.String("vault", "", "vault to list")
	if _, err := parseInterspersed(fs, args); err != nil {
		return exitError, err
	}
	v, err := a.pickVault(*vaultName, false)
	if err != nil {
		return exitError, err
	}
	names, err := v.Names()
	if err != nil {
		return exitError, err
	}
	for _, n := range names {
		fmt.Fprintln(a.Stdout, n)
	}
	return exitOK, nil
}

func (a *App) vaultGet(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet(a, "vault get", "vault get [--vault V] [--reveal] NAME")
	vaultName := fs.String("vault", "", "vault to read")
	reveal := fs.Bool("reveal", false, "print even when standard output is a terminal")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError, err
	}
	if len(pos) != 1 {
		return exitError, errors.New("vault get takes exactly one name")
	}
	if a.StdoutIsTerminal() && !*reveal {
		return exitError, errors.New("refusing to print a value to a terminal; pipe it, or pass --reveal")
	}
	v, err := a.pickVault(*vaultName, false)
	if err != nil {
		return exitError, err
	}
	vals, err := v.Read(ctx, pos)
	if err != nil {
		return exitError, err
	}
	val, ok := vals[pos[0]]
	if !ok {
		return exitError, fmt.Errorf("%s is not in vault %s", pos[0], v.Name())
	}
	if _, err := io.WriteString(a.RawStdout, val); err != nil {
		return exitError, err
	}
	return exitOK, nil
}

// readValue reads a value from stdin: hidden input on a terminal, otherwise
// everything up to EOF with one trailing newline removed.
func (a *App) readValue(name string) (string, error) {
	var v string
	if a.StdinIsTerminal() {
		s, err := a.ReadSecret(fmt.Sprintf("Value for %s: ", name))
		if err != nil {
			return "", err
		}
		v = s
	} else {
		b, err := io.ReadAll(bufio.NewReader(a.Stdin))
		if err != nil {
			return "", err
		}
		v = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	}
	if v == "" {
		return "", errors.New("refusing to store an empty value (empty stdin?)")
	}
	redact.Register(v)
	return v, nil
}

func (a *App) vaultSet(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet(a, "vault set", "vault set [--vault V] NAME < value")
	vaultName := fs.String("vault", "", "vault to write")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError, err
	}
	if len(pos) != 1 {
		return exitError, errors.New("vault set takes exactly one name; the value comes on stdin")
	}
	if err := vault.ValidName(pos[0]); err != nil {
		return exitError, err
	}
	v, err := a.pickVault(*vaultName, false)
	if err != nil {
		return exitError, err
	}
	val, err := a.readValue(pos[0])
	if err != nil {
		return exitError, err
	}
	if err := v.Write(ctx, pos[0], val); err != nil {
		return exitError, err
	}
	fmt.Fprintf(a.Stderr, "Set %s in vault %s.\n", pos[0], v.Name())
	return exitOK, nil
}

func (a *App) vaultVerify(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet(a, "vault verify", "vault verify [--vault V] NAME < value")
	vaultName := fs.String("vault", "", "vault to read")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError, err
	}
	if len(pos) != 1 {
		return exitError, errors.New("vault verify takes exactly one name; the value comes on stdin")
	}
	v, err := a.pickVault(*vaultName, false)
	if err != nil {
		return exitError, err
	}
	want, err := a.readValue(pos[0])
	if err != nil {
		return exitError, err
	}
	vals, err := v.Read(ctx, pos)
	if err != nil {
		return exitError, err
	}
	got, ok := vals[pos[0]]
	switch {
	case !ok:
		return exitError, fmt.Errorf("%s is not in vault %s", pos[0], v.Name())
	case subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1:
		fmt.Fprintln(a.Stdout, "match")
		return exitOK, nil
	}
	fmt.Fprintln(a.Stdout, "differs")
	return exitPending, nil
}

func (a *App) vaultUnset(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet(a, "vault unset", "vault unset [--vault V] NAME")
	vaultName := fs.String("vault", "", "vault to change")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError, err
	}
	if len(pos) != 1 {
		return exitError, errors.New("vault unset takes exactly one name")
	}
	v, err := a.pickVault(*vaultName, false)
	if err != nil {
		return exitError, err
	}
	entries, err := v.Entries(pos)
	if err != nil {
		return exitError, err
	}
	if !entries[pos[0]].Present {
		return exitError, fmt.Errorf("%s is not in vault %s", pos[0], v.Name())
	}
	if err := v.Trash(ctx, pos, time.Now().UTC().Format("20060102T150405Z")); err != nil {
		return exitError, err
	}
	fmt.Fprintf(a.Stderr, "Moved %s to the trash of vault %s.\n", pos[0], v.Name())
	return exitOK, nil
}

func (a *App) vaultRun(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet(a, "vault run", "vault run [--vault V] NAME... -- COMMAND [ARGS...]")
	vaultName := fs.String("vault", "", "vault to read")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError, err
	}
	sep := -1
	for i, p := range pos {
		if p == "--" {
			sep = i
			break
		}
	}
	if sep < 1 || sep == len(pos)-1 {
		return exitError, errors.New("usage: vault run NAME... -- COMMAND [ARGS...]")
	}
	names, command := pos[:sep], pos[sep+1:]
	v, err := a.pickVault(*vaultName, false)
	if err != nil {
		return exitError, err
	}
	vals, err := v.Read(ctx, names)
	if err != nil {
		return exitError, err
	}
	for _, n := range names {
		if _, ok := vals[n]; !ok {
			return exitError, fmt.Errorf("%s is not in vault %s", n, v.Name())
		}
	}
	// The child gets exactly the requested names from this vault: anything
	// else the vault defines is stripped from the inherited environment.
	all, err := v.Names()
	if err != nil {
		return exitError, err
	}
	strip := map[string]bool{}
	for _, n := range all {
		strip[n] = true
	}
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if !strip[k] {
			env = append(env, kv)
		}
	}
	for _, n := range names {
		env = append(env, n+"="+vals[n])
	}
	if err := a.Exec(command[0], command, env); err != nil {
		return exitError, fmt.Errorf("run %s: %w", command[0], err)
	}
	return exitOK, nil
}
