package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/frederikb96/tandemvault/internal/config"
	"github.com/frederikb96/tandemvault/internal/onepassword"
	"github.com/frederikb96/tandemvault/internal/onepassword/optest"
	"github.com/frederikb96/tandemvault/internal/redact"
	"github.com/frederikb96/tandemvault/internal/testutil"
	"github.com/frederikb96/tandemvault/internal/vault"
)

func init() { vault.ScryptWorkFactor = 10 }

const mark = "SECRETMARK"

type env struct {
	t      *testing.T
	dir    string
	config string
	op     *optest.Fake
	out    bytes.Buffer // everything printed except vault get
	execed []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	testutil.RequireSops(t)
	redact.Reset()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	dir := t.TempDir()
	key, _ := testutil.AgeKeyFile(t, dir)
	cfg := `onepassword:
  account: test
vaults:
  open:
    type: sops-dotenv
    path: open.env
    age_key_file: ` + key + `
  sealed:
    type: age-dir
    dir: sealed
    passphrase: op://Private/sealed passphrase/password
`
	e := &env{t: t, dir: dir, config: filepath.Join(dir, "config.yaml"), op: optest.NewFake("Private")}
	e.op.Secrets["op://Private/sealed passphrase/password"] = "a sealed vault passphrase-" + mark
	if err := os.WriteFile(e.config, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.run("", "vault", "init", "--vault", "open"); code != 0 {
		t.Fatalf("init open: %s", e.out.String())
	}
	if code, _ := e.run("", "vault", "init", "--vault", "sealed"); code != 0 {
		t.Fatalf("init sealed: %s", e.out.String())
	}
	return e
}

// run executes one command. stdin is fed to the command; raw is what vault get printed.
func (e *env) run(stdin string, args ...string) (code int, raw string) {
	e.t.Helper()
	var rawOut bytes.Buffer
	app := &App{
		Version:          "test",
		Stdin:            strings.NewReader(stdin),
		Stdout:           &e.out,
		Stderr:           &e.out,
		RawStdout:        &rawOut,
		StdinIsTerminal:  func() bool { return false },
		StdoutIsTerminal: func() bool { return false },
		ReadSecret:       func(string) (string, error) { e.t.Fatal("unexpected prompt"); return "", nil },
		NewBackend:       func(context.Context, *config.Config) (onepassword.Backend, error) { return e.op, nil },
		Exec: func(_ string, argv []string, env []string) error {
			e.execed = append(append([]string{}, argv...), env...)
			return nil
		},
	}
	code = app.Run(context.Background(), append([]string{"--config", e.config}, args...))
	if strings.Contains(e.out.String(), mark) {
		e.t.Fatalf("output contains a value:\n%s", e.out.String())
	}
	return code, rawOut.String()
}

func TestVaultCommands(t *testing.T) {
	e := newEnv(t)
	for _, v := range []string{"open", "sealed"} {
		if code, _ := e.run("value-"+mark+"\n", "vault", "set", "--vault", v, "API_TOKEN"); code != 0 {
			t.Fatalf("%s set: %s", v, e.out.String())
		}
		code, raw := e.run("", "vault", "get", "API_TOKEN", "--vault", v)
		if code != 0 || raw != "value-"+mark {
			t.Fatalf("%s get: code %d, trailing newline must be stripped on set", v, code)
		}
		e.run("other-"+mark, "vault", "set", "--vault", v, "OTHER")
		e.out.Reset()
		e.run("", "vault", "names", "--vault", v)
		if e.out.String() != "API_TOKEN\nOTHER\n" {
			t.Fatalf("%s names: %q", v, e.out.String())
		}
		if code, _ := e.run("", "vault", "set", "--vault", v, "EMPTY"); code == 0 {
			t.Fatal("empty value stored")
		}
		t.Setenv("OTHER", "inherited")
		if code, _ := e.run("", "vault", "run", "--vault", v, "API_TOKEN", "--", "printenv", "API_TOKEN"); code != 0 {
			t.Fatalf("run: %s", e.out.String())
		}
		joined := strings.Join(e.execed, "\n")
		if !strings.Contains(joined, "API_TOKEN=value-"+mark) || strings.Contains(joined, "OTHER=") {
			t.Fatalf("%s run env wrong", v)
		}
		if code, _ := e.run("", "vault", "unset", "--vault", v, "OTHER"); code != 0 {
			t.Fatalf("unset: %s", e.out.String())
		}
		e.out.Reset()
		e.run("", "vault", "names", "--vault", v)
		if e.out.String() != "API_TOKEN\n" {
			t.Fatalf("%s names after unset: %q", v, e.out.String())
		}
	}
}

func TestVaultGetRefusesTerminal(t *testing.T) {
	e := newEnv(t)
	e.run("v-"+mark, "vault", "set", "--vault", "open", "X")
	app := &App{Stdout: &e.out, Stderr: &e.out, RawStdout: &e.out, StdoutIsTerminal: func() bool { return true }}
	code := app.Run(context.Background(), []string{"--config", e.config, "vault", "get", "--vault", "open", "X"})
	if code == 0 || !strings.Contains(e.out.String(), "refusing to print a value to a terminal") {
		t.Fatalf("code %d: %s", code, e.out.String())
	}
}

func TestVaultSetNeverTakesValueFromArgs(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.run("", "vault", "set", "--vault", "open", "X", "the-value"); code == 0 {
		t.Fatal("value accepted as an argument")
	}
}

func TestLinkStatusUnlink(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.run("", "link", "--vault", "sealed", "--prefix", "SHOP", "--passkey", "--no-passkey", "Shop"); code == 0 {
		t.Fatal("contradicting passkey flags accepted")
	}
	if code, _ := e.run("", "link", "--vault", "sealed", "--prefix", "SHOP", "--op-vault", "Private", "Shop"); code == 0 {
		t.Fatal("vault title accepted for --op-vault")
	}
	if code, _ := e.run("", "link", "--vault", "sealed", "--prefix", "SHOP", "Shop"); code != 0 {
		t.Fatalf("link: %s", e.out.String())
	}
	if code, _ := e.run("", "link", "--vault", "sealed", "--prefix", "SHOP", "--no-passkey", "Shop"); code == 0 {
		t.Fatal("duplicate link accepted")
	}
	e.out.Reset()
	if code, _ := e.run("", "status", "--local"); code != exitPending || !strings.Contains(e.out.String(), `link to "Shop" pending`) {
		t.Fatalf("status: %d %s", code, e.out.String())
	}
	if code, _ := e.run("", "unlink", "--keep", "both", "SHOP"); code != 0 {
		t.Fatalf("unlink: %s", e.out.String())
	}
	if code, _ := e.run("", "status", "--local", "--quiet"); code != exitOK {
		t.Fatal("status not clean after unlink")
	}
}

func TestSyncFlow(t *testing.T) {
	e := newEnv(t)
	id := e.op.Add("Private", "Shop", map[onepassword.Field]string{onepassword.Username: "me-" + mark, onepassword.Password: "pw-" + mark})
	if code, _ := e.run("", "link", "--vault", "sealed", "--prefix", "SHOP", "--no-passkey", "--fields", "username,password", "Shop"); code != 0 {
		t.Fatalf("link: %s", e.out.String())
	}
	if code, _ := e.run("", "sync", "--dry-run"); code != exitPending || e.op.Writes() != 0 {
		t.Fatalf("dry run: %s", e.out.String())
	}
	if code, _ := e.run("n\n", "sync"); code != exitPending || !strings.Contains(e.out.String(), "Aborted") {
		t.Fatalf("decline: %s", e.out.String())
	}
	if _, err := os.Stat(filepath.Join(e.dir, "sealed", "SHOP_USER.age")); err == nil {
		t.Fatal("written after declining")
	}
	e.out.Reset()
	if code, _ := e.run("y\n", "sync"); code != exitOK {
		t.Fatalf("sync: %s", e.out.String())
	}
	if !strings.Contains(e.out.String(), "SHOP_PASSWORD") || !strings.Contains(e.out.String(), "create from 1Password") {
		t.Fatalf("plan output: %s", e.out.String())
	}
	if code, _ := e.run("", "status", "--local"); code != exitOK {
		t.Fatalf("status after sync: %s", e.out.String())
	}

	// An agent changes the vault; status --local sees it without any key.
	e.run("new-pw-"+mark, "vault", "set", "--vault", "sealed", "SHOP_PASSWORD")
	e.out.Reset()
	if code, _ := e.run("", "status", "--local"); code != exitPending || !strings.Contains(e.out.String(), "SHOP_PASSWORD changed in the vault") {
		t.Fatalf("status: %s", e.out.String())
	}
	if code, _ := e.run("yes\n", "sync"); code != exitOK {
		t.Fatalf("sync: %s", e.out.String())
	}
	if e.op.Item(id).Values[onepassword.Password] != "new-pw-"+mark {
		t.Fatal("1Password not updated")
	}
	e.out.Reset()
	if code, _ := e.run("", "sync"); code != exitOK || !strings.Contains(e.out.String(), "Nothing to do") {
		t.Fatalf("idle sync: %s", e.out.String())
	}
}

func TestSyncRefusesConflictCopies(t *testing.T) {
	e := newEnv(t)
	if err := os.WriteFile(filepath.Join(e.dir, "open.sync-conflict-20260101-000000-AAAAAAA.env"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e.op.Add("Private", "Shop", nil)
	e.run("", "link", "--vault", "sealed", "--prefix", "SHOP", "--no-passkey", "Shop")
	e.op.Calls = nil
	if code, _ := e.run("y\n", "sync"); code != exitError || !strings.Contains(e.out.String(), "conflict copies") {
		t.Fatalf("code %d: %s", code, e.out.String())
	}
	if e.op.Writes() != 0 || len(e.op.Calls) != 0 {
		t.Fatal("1Password reached despite conflict copies")
	}
}

func TestVaultsListsIDs(t *testing.T) {
	e := newEnv(t)
	e.out.Reset()
	if code, _ := e.run("", "vaults"); code != 0 || !strings.Contains(e.out.String(), e.op.VaultID("Private")+"  Private") {
		t.Fatalf("vaults: %s", e.out.String())
	}
}

func TestRedactingWriterMasksRegisteredValues(t *testing.T) {
	redact.Reset()
	var buf bytes.Buffer
	w := redact.Writer(&buf)
	redact.Register("hunter2hunter2")
	w.Write([]byte("error: bad value hunter2hunter2 here\n"))
	if strings.Contains(buf.String(), "hunter2") {
		t.Fatalf("not masked: %s", buf.String())
	}
}

func TestParseInterspersed(t *testing.T) {
	fs := newFlagSet(&App{Stderr: &bytes.Buffer{}}, "x", "x")
	v := fs.String("vault", "", "")
	r := fs.Bool("reveal", false, "")
	pos, err := parseInterspersed(fs, []string{"NAME", "--vault", "open", "--reveal", "--", "cmd", "--vault", "x"})
	if err != nil {
		t.Fatal(err)
	}
	if *v != "open" || !*r || strings.Join(pos, " ") != "NAME -- cmd --vault x" {
		t.Fatalf("vault %q reveal %v pos %v", *v, *r, pos)
	}
}

func TestLeaseWorkflowTwoSyncs(t *testing.T) {
	e := newEnv(t)
	id := e.op.Add("Private", "www.example-shop.com", map[onepassword.Field]string{onepassword.Username: "me-" + mark, onepassword.Password: "old-" + mark})
	if code, _ := e.run("", "link", "--lease", "--vault", "sealed", "--prefix", "SHOP", "--fields", "username,password", "example-shop"); code != 0 {
		t.Fatalf("link: %s", e.out.String())
	}
	// Sync 1: pull.
	if code, _ := e.run("y\n", "sync"); code != exitOK {
		t.Fatalf("sync 1: %s", e.out.String())
	}
	e.out.Reset()
	e.run("", "status", "--local")
	if !strings.Contains(e.out.String(), "Leased, give back with tandemvault return when done: sealed/SHOP") {
		t.Fatalf("status: %s", e.out.String())
	}
	// Rotate in the vault, then return: a sync is needed.
	e.run("new-"+mark, "vault", "set", "--vault", "sealed", "SHOP_PASSWORD")
	e.out.Reset()
	if code, _ := e.run("", "return", "SHOP"); code != exitPending || !strings.Contains(e.out.String(), "Marked sealed/SHOP to return") {
		t.Fatalf("return: %d %s", code, e.out.String())
	}
	// Sync 2: write back, check, delete.
	if code, _ := e.run("y\n", "sync"); code != exitOK {
		t.Fatalf("sync 2: %s", e.out.String())
	}
	if e.op.Item(id).Values[onepassword.Password] != "new-"+mark {
		t.Fatal("not written back")
	}
	e.out.Reset()
	e.run("", "vault", "names", "--vault", "sealed")
	if strings.Contains(e.out.String(), "SHOP_") {
		t.Fatalf("vault copy left: %s", e.out.String())
	}
	if code, _ := e.run("", "status", "--local"); code != exitOK {
		t.Fatalf("status after return: %s", e.out.String())
	}
}

func TestReturnUnchangedIsImmediate(t *testing.T) {
	e := newEnv(t)
	e.op.Add("Private", "Shop", map[onepassword.Field]string{onepassword.Password: "pw-" + mark})
	e.run("", "link", "--lease", "--vault", "open", "--prefix", "SHOP", "--fields", "password", "Shop")
	e.run("y\n", "sync")
	e.op.Calls = nil
	e.out.Reset()
	if code, _ := e.run("", "return", "SHOP"); code != exitOK || !strings.Contains(e.out.String(), "Returned open/SHOP") {
		t.Fatalf("return: %d %s", code, e.out.String())
	}
	if len(e.op.Calls) != 0 {
		t.Fatal("1Password reached for an unchanged return")
	}
	e.out.Reset()
	e.run("", "vault", "names", "--vault", "open")
	if strings.Contains(e.out.String(), "SHOP_PASSWORD") {
		t.Fatal("vault copy left")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "open.trash.env")); err == nil {
		t.Fatal("trash copy made")
	}
}

func TestUnlinkKeepNoneRetires(t *testing.T) {
	e := newEnv(t)
	id := e.op.Add("Private", "Old", map[onepassword.Field]string{onepassword.Password: "pw-" + mark})
	if code, _ := e.run("", "unlink", "--keep", "none", "NOPE"); code == 0 {
		t.Fatal("unknown prefix accepted")
	}
	e.run("", "link", "--vault", "sealed", "--prefix", "OLD", "--fields", "password", "Old")
	e.run("y\n", "sync")
	if code, _ := e.run("", "unlink", "--keep", "none", "OLD"); code != 0 {
		t.Fatalf("unlink: %s", e.out.String())
	}
	if code, _ := e.run("y\n", "sync"); code != exitOK {
		t.Fatalf("sync: %s", e.out.String())
	}
	if !e.op.Item(id).Deleted {
		t.Fatal("item not retired")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "sealed", "OLD_PASSWORD.age")); err == nil {
		t.Fatal("vault copy left")
	}
}

func TestVaultVerify(t *testing.T) {
	e := newEnv(t)
	for _, v := range []string{"open", "sealed"} {
		e.run("value-"+mark, "vault", "set", "--vault", v, "X")
		e.out.Reset()
		if code, _ := e.run("value-"+mark+"\n", "vault", "verify", "--vault", v, "X"); code != exitOK || e.out.String() != "match\n" {
			t.Fatalf("%s match: %d %q", v, code, e.out.String())
		}
		e.out.Reset()
		if code, _ := e.run("other-"+mark, "vault", "verify", "--vault", v, "X"); code != exitPending || e.out.String() != "differs\n" {
			t.Fatalf("%s differs: %d %q", v, code, e.out.String())
		}
	}
}
