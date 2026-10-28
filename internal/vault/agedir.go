package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/frederikb96/tandemvault/internal/config"
	"github.com/frederikb96/tandemvault/internal/redact"
)

// MinPassphraseLength is the shortest passphrase Init accepts.
const MinPassphraseLength = 12

// ScryptWorkFactor is the scrypt cost (log2 N) Init seals new identities
// with. Tests lower it to keep runs fast.
var ScryptWorkFactor = 18

// AgeDir is a directory of armored age files, one per name.
type AgeDir struct {
	name          string
	dir           string
	identityPath  string
	recipientPath string
	passphrase    PassphraseFunc

	identity *age.X25519Identity
}

func (a *AgeDir) Name() string { return a.name }
func (a *AgeDir) Type() string { return config.TypeAgeDir }

func (a *AgeDir) file(name string) string { return filepath.Join(a.dir, name+".age") }

func (a *AgeDir) Names() ([]string, error) {
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		n, ok := strings.CutSuffix(e.Name(), ".age")
		if !ok || e.IsDir() || ValidName(n) != nil {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

func (a *AgeDir) Entries(names []string) (map[string]Entry, error) {
	out := make(map[string]Entry, len(names))
	for _, n := range names {
		if err := ValidName(n); err != nil {
			return nil, err
		}
		b, err := os.ReadFile(a.file(n))
		if errors.Is(err, os.ErrNotExist) {
			out[n] = Entry{}
			continue
		}
		if err != nil {
			return nil, err
		}
		st, err := os.Stat(a.file(n))
		if err != nil {
			return nil, err
		}
		out[n] = Entry{Present: true, Fingerprint: fingerprint(b), ModTime: st.ModTime().UTC()}
	}
	return out, nil
}

// Unlock unseals the identity with the passphrase and checks that it still
// derives the published recipient. The recipient file can be written without
// the passphrase, so a swapped recipient would otherwise redirect every later
// write to someone else's key without any error.
func (a *AgeDir) Unlock(ctx context.Context) error {
	if a.identity != nil {
		return nil
	}
	if a.passphrase == nil {
		return fmt.Errorf("vault %s: no passphrase source", a.name)
	}
	sealed, err := os.ReadFile(a.identityPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("vault %s is not initialised (no %s)", a.name, a.identityPath)
		}
		return err
	}
	pass, err := a.passphrase(ctx)
	if err != nil {
		return fmt.Errorf("vault %s: passphrase: %w", a.name, err)
	}
	redact.Register(pass)
	scrypt, err := age.NewScryptIdentity(pass)
	if err != nil {
		return err
	}
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(sealed)), scrypt)
	if err != nil {
		return fmt.Errorf("vault %s: could not unseal the identity (wrong passphrase?)", a.name)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("vault %s: could not unseal the identity", a.name)
	}
	id, err := parseX25519(plain)
	if err != nil {
		return fmt.Errorf("vault %s: the sealed identity is not an X25519 age identity", a.name)
	}
	redact.Register(id.String())
	if published, err := a.readRecipient(); err == nil {
		if published.String() != id.Recipient().String() {
			return fmt.Errorf("vault %s: %s does not match the sealed identity, it may have been tampered with", a.name, a.recipientPath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	a.identity = id
	return nil
}

func (a *AgeDir) readRecipient() (*age.X25519Recipient, error) {
	b, err := os.ReadFile(a.recipientPath)
	if err != nil {
		return nil, err
	}
	r, err := age.ParseX25519Recipient(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("vault %s: %s does not hold an age recipient", a.name, a.recipientPath)
	}
	return r, nil
}

func (a *AgeDir) Read(ctx context.Context, names []string) (map[string]string, error) {
	if err := a.Unlock(ctx); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, n := range names {
		if err := ValidName(n); err != nil {
			return nil, err
		}
		b, err := os.ReadFile(a.file(n))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		r, err := age.Decrypt(armor.NewReader(bytes.NewReader(b)), a.identity)
		if err != nil {
			return nil, fmt.Errorf("could not decrypt %s: %w", a.file(n), err)
		}
		plain, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("could not decrypt %s: %w", a.file(n), err)
		}
		redact.Register(string(plain))
		out[n] = string(plain)
	}
	return out, nil
}

// Write encrypts value to the published recipient. Adding a new entry needs
// no passphrase; replacing an existing one unlocks the vault first, so only
// someone who can read the vault can overwrite what is in it.
func (a *AgeDir) Write(ctx context.Context, name, value string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	redact.Register(value)
	if _, err := os.Stat(a.file(name)); err == nil {
		if err := a.Unlock(ctx); err != nil {
			return err
		}
	}
	recipient, err := a.readRecipient()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("vault %s is not initialised (no %s)", a.name, a.recipientPath)
		}
		return err
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, value); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := aw.Close(); err != nil {
		return err
	}
	buf.WriteString("\n")
	return WriteFileAtomic(a.file(name), buf.Bytes(), 0o600)
}

// Trash moves entries into <dir>/.trash/<stamp>/. It unlocks the vault first,
// like replacing an entry does.
func (a *AgeDir) Trash(ctx context.Context, names []string, stamp string) error {
	if err := a.Unlock(ctx); err != nil {
		return err
	}
	dest := filepath.Join(a.dir, ".trash", stamp)
	for _, n := range names {
		if err := ValidName(n); err != nil {
			return err
		}
		if _, err := os.Stat(a.file(n)); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := os.MkdirAll(dest, 0o700); err != nil {
			return err
		}
		if err := os.Rename(a.file(n), freePath(filepath.Join(dest, n), ".age")); err != nil {
			return err
		}
	}
	return nil
}

func (a *AgeDir) ConflictCopies() ([]string, error) {
	var found []string
	entries, err := os.ReadDir(a.dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".sync-conflict-") {
			found = append(found, filepath.Join(a.dir, e.Name()))
		}
	}
	for _, p := range []string{a.identityPath, a.recipientPath} {
		c, err := ConflictCopiesOf(p)
		if err != nil {
			return nil, err
		}
		found = append(found, c...)
	}
	return found, nil
}

// Init generates an identity, seals it with the passphrase and publishes its recipient.
func (a *AgeDir) Init(ctx context.Context, _ InitOptions) error {
	for _, p := range []string{a.identityPath, a.recipientPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s already exists", p)
		}
	}
	if a.passphrase == nil {
		return fmt.Errorf("vault %s: no passphrase source", a.name)
	}
	pass, err := a.passphrase(ctx)
	if err != nil {
		return fmt.Errorf("vault %s: passphrase: %w", a.name, err)
	}
	if len(pass) < MinPassphraseLength {
		return fmt.Errorf("use a passphrase of at least %d characters", MinPassphraseLength)
	}
	redact.Register(pass)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	scrypt, err := age.NewScryptRecipient(pass)
	if err != nil {
		return err
	}
	scrypt.SetWorkFactor(ScryptWorkFactor)
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, scrypt)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, id.String()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := aw.Close(); err != nil {
		return err
	}
	buf.WriteString("\n")
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return err
	}
	if err := WriteFileAtomic(a.identityPath, buf.Bytes(), 0o600); err != nil {
		return err
	}
	if err := WriteFileAtomic(a.recipientPath, []byte(id.Recipient().String()+"\n"), 0o600); err != nil {
		return err
	}
	a.identity = id
	return nil
}

// freePath returns base+ext, or base-2+ext, base-3+ext, ... whichever does not exist yet.
func freePath(base, ext string) string {
	p := base + ext
	for i := 2; ; i++ {
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			return p
		}
		p = fmt.Sprintf("%s-%d%s", base, i, ext)
	}
}

// parseX25519 reads an identity file as age-keygen writes it, comments included.
func parseX25519(b []byte) (*age.X25519Identity, error) {
	ids, err := age.ParseIdentities(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			return x, nil
		}
	}
	return nil, errors.New("no X25519 identity")
}
