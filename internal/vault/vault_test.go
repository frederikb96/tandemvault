package vault

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/frederikb96/tandemvault/internal/config"
	"github.com/frederikb96/tandemvault/internal/testutil"
)

func init() { ScryptWorkFactor = 10 }

const pass = "correct horse battery staple"

func newSops(t *testing.T) (*SopsDotenv, string) {
	t.Helper()
	testutil.RequireSops(t)
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	key, recipient := testutil.AgeKeyFile(t, dir)
	c := &config.Config{Vaults: map[string]config.Vault{"open": {Type: config.TypeSopsDotenv, Path: filepath.Join(dir, ".sops.env"), AgeKeyFile: key}}}
	v, err := Open(c, "open", nil)
	if err != nil {
		t.Fatal(err)
	}
	s := v.(*SopsDotenv)
	if err := s.Init(context.Background(), InitOptions{AgeRecipients: []string{recipient}}); err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func newAgeDir(t *testing.T, calls *int) *AgeDir {
	t.Helper()
	dir := t.TempDir()
	c := &config.Config{Vaults: map[string]config.Vault{"sealed": {Type: config.TypeAgeDir, Dir: filepath.Join(dir, "sealed"), Identity: filepath.Join(dir, "sealed-identity.age"), Recipient: filepath.Join(dir, "sealed.recipient"), Passphrase: "prompt"}}}
	v, err := Open(c, "sealed", func(context.Context) (string, error) {
		if calls != nil {
			*calls++
		}
		return pass, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	a := v.(*AgeDir)
	if err := a.Init(context.Background(), InitOptions{}); err != nil {
		t.Fatal(err)
	}
	a.identity = nil // start locked, as a fresh process would
	if calls != nil {
		*calls = 0
	}
	return a
}

func TestSopsDotenvRoundTrip(t *testing.T) {
	s, _ := newSops(t)
	ctx := context.Background()
	values := map[string]string{
		"PLAIN":    "hunter2-plain-value",
		"QUOTED":   `"wrapped in quotes"`,
		"SINGLE":   `'single'`,
		"SPECIALS": `p@ss w0rd $HOME \n "x"`,
	}
	for k, v := range values {
		if err := s.Write(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	s.cache = nil
	got, err := s.Read(ctx, []string{"PLAIN", "QUOTED", "SINGLE", "SPECIALS", "MISSING"})
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range values {
		if got[k] != v {
			t.Errorf("%s: round trip changed the value", k)
		}
	}
	if _, ok := got["MISSING"]; ok {
		t.Error("absent name returned")
	}
	names, err := s.Names()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "PLAIN,QUOTED,SINGLE,SPECIALS" {
		t.Fatalf("names %v", names)
	}
}

func TestSopsDotenvFingerprintsMoveOnlyForChangedEntry(t *testing.T) {
	s, _ := newSops(t)
	ctx := context.Background()
	for _, k := range []string{"A", "B"} {
		if err := s.Write(ctx, k, "value-"+k); err != nil {
			t.Fatal(err)
		}
	}
	before, err := s.Entries([]string{"A", "B", "C"})
	if err != nil {
		t.Fatal(err)
	}
	if before["C"].Present || !before["A"].Present {
		t.Fatal("presence wrong")
	}
	if err := s.Write(ctx, "B", "changed"); err != nil {
		t.Fatal(err)
	}
	after, err := s.Entries([]string{"A", "B"})
	if err != nil {
		t.Fatal(err)
	}
	if before["A"].Fingerprint != after["A"].Fingerprint {
		t.Error("untouched entry's fingerprint moved")
	}
	if before["B"].Fingerprint == after["B"].Fingerprint {
		t.Error("changed entry's fingerprint did not move")
	}
}

func TestSopsDotenvTrash(t *testing.T) {
	s, _ := newSops(t)
	ctx := context.Background()
	if err := s.Write(ctx, "GONE", "trash-me-value"); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(ctx, "STAYS", "keep-me-value"); err != nil {
		t.Fatal(err)
	}
	if err := s.Trash(ctx, []string{"GONE"}, "20260101T000000Z"); err != nil {
		t.Fatal(err)
	}
	names, _ := s.Names()
	if strings.Join(names, ",") != "STAYS" {
		t.Fatalf("names after trash: %v", names)
	}
	trash := &SopsDotenv{name: "trash", path: s.TrashPath(), ageKeyFile: s.ageKeyFile}
	got, err := trash.Read(ctx, []string{"GONE__20260101T000000Z"})
	if err != nil {
		t.Fatal(err)
	}
	if got["GONE__20260101T000000Z"] != "trash-me-value" {
		t.Fatal("trashed value not in the trash file")
	}
}

func TestConflictCopies(t *testing.T) {
	s, dir := newSops(t)
	if c, _ := s.ConflictCopies(); len(c) != 0 {
		t.Fatalf("unexpected conflict copies %v", c)
	}
	copyPath := filepath.Join(dir, ".sops.sync-conflict-20260101-120000-ABCDEFG.env")
	if err := os.WriteFile(copyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(dir, "settings.sync-conflict-20260101-120000-ABCDEFG.json")
	if err := os.WriteFile(unrelated, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := s.ConflictCopies()
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 1 || c[0] != copyPath {
		t.Fatalf("conflict copies %v", c)
	}
}

func TestAgeDirWriteNeedsNoPassphraseReplaceDoes(t *testing.T) {
	calls := 0
	a := newAgeDir(t, &calls)
	ctx := context.Background()
	if err := a.Write(ctx, "NEW", "first-value"); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("adding an entry asked for the passphrase")
	}
	if err := a.Write(ctx, "NEW", "second-value"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("replacing asked %d times, want once", calls)
	}
	got, err := a.Read(ctx, []string{"NEW", "ABSENT"})
	if err != nil {
		t.Fatal(err)
	}
	if got["NEW"] != "second-value" || len(got) != 1 {
		t.Fatal("read back wrong")
	}
	if calls != 1 {
		t.Fatal("unlocked twice in one process")
	}
	st, _ := os.Stat(a.file("NEW"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("entry mode %v", st.Mode().Perm())
	}
}

func TestAgeDirWrongPassphrase(t *testing.T) {
	a := newAgeDir(t, nil)
	a.passphrase = func(context.Context) (string, error) { return "wrong passphrase entirely", nil }
	if err := a.Write(context.Background(), "X", "v"); err != nil {
		t.Fatal(err)
	}
	_, err := a.Read(context.Background(), []string{"X"})
	if err == nil || !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("err = %v", err)
	}
}

func TestAgeDirTamperedRecipient(t *testing.T) {
	a := newAgeDir(t, nil)
	other := newAgeDir(t, nil)
	b, _ := os.ReadFile(other.recipientPath)
	if err := os.WriteFile(a.recipientPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	err := a.Unlock(context.Background())
	if err == nil || !strings.Contains(err.Error(), "tampered") {
		t.Fatalf("err = %v", err)
	}
}

func TestAgeDirTrashAndNames(t *testing.T) {
	a := newAgeDir(t, nil)
	ctx := context.Background()
	for _, n := range []string{"A_ONE", "B_TWO"} {
		if err := a.Write(ctx, n, "v-"+n); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Trash(ctx, []string{"A_ONE"}, "20260101T000000Z"); err != nil {
		t.Fatal(err)
	}
	names, _ := a.Names()
	if strings.Join(names, ",") != "B_TWO" {
		t.Fatalf("names %v", names)
	}
	if _, err := os.Stat(filepath.Join(a.dir, ".trash", "20260101T000000Z", "A_ONE.age")); err != nil {
		t.Fatal("trashed entry missing")
	}
}

func TestAgeDirInitRefusesShortPassphraseAndExisting(t *testing.T) {
	a := newAgeDir(t, nil)
	if err := a.Init(context.Background(), InitOptions{}); err == nil {
		t.Fatal("init over an existing vault succeeded")
	}
	dir := t.TempDir()
	short := &AgeDir{name: "s", dir: filepath.Join(dir, "d"), identityPath: filepath.Join(dir, "i"), recipientPath: filepath.Join(dir, "r"),
		passphrase: func(context.Context) (string, error) { return "short", nil }}
	if err := short.Init(context.Background(), InitOptions{}); err == nil {
		t.Fatal("short passphrase accepted")
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"A", "_X", "abc_1"} {
		if ValidName(ok) != nil {
			t.Errorf("%s rejected", ok)
		}
	}
	for _, bad := range []string{"", "1A", "A-B", "../x", "A B"} {
		if ValidName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestOpenUnknown(t *testing.T) {
	_, err := Open(&config.Config{}, "nope", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAgeDirReadsAgeKeygenStyleIdentity(t *testing.T) {
	a := newAgeDir(t, nil)
	id, _ := age.GenerateX25519Identity()
	keygen := "# created: 2026-01-01T00:00:00Z\n# public key: " + id.Recipient().String() + "\n" + id.String() + "\n"
	sr, _ := age.NewScryptRecipient(pass)
	sr.SetWorkFactor(10)
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, _ := age.Encrypt(aw, sr)
	w.Write([]byte(keygen))
	w.Close()
	aw.Close()
	os.WriteFile(a.identityPath, buf.Bytes(), 0o600)
	os.WriteFile(a.recipientPath, []byte(id.Recipient().String()+"\n"), 0o600)
	if err := a.Unlock(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveDeletesWithoutTrashOrUnlock(t *testing.T) {
	ctx := context.Background()
	calls := 0
	a := newAgeDir(t, &calls)
	a.Write(ctx, "GONE", "v1")
	a.Write(ctx, "STAYS", "v2")
	if err := a.Remove(ctx, []string{"GONE", "ABSENT"}); err != nil {
		t.Fatal(err)
	}
	names, _ := a.Names()
	if strings.Join(names, ",") != "STAYS" || calls != 0 {
		t.Fatalf("names %v, passphrase asked %d times", names, calls)
	}
	if _, err := os.Stat(filepath.Join(a.dir, ".trash")); err == nil {
		t.Fatal("trash made")
	}

	s, dir := newSops(t)
	s.Write(ctx, "GONE", "v1")
	s.Write(ctx, "STAYS", "v2")
	if err := s.Remove(ctx, []string{"GONE", "ABSENT"}); err != nil {
		t.Fatal(err)
	}
	names, _ = s.Names()
	if strings.Join(names, ",") != "STAYS" {
		t.Fatalf("names %v", names)
	}
	if _, err := os.Stat(filepath.Join(dir, ".sops.trash.env")); err == nil {
		t.Fatal("trash made")
	}
}
