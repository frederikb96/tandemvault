package engine

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/frederikb96/tandemvault/internal/config"
	"github.com/frederikb96/tandemvault/internal/mapping"
	"github.com/frederikb96/tandemvault/internal/onepassword"
	"github.com/frederikb96/tandemvault/internal/onepassword/optest"
	"github.com/frederikb96/tandemvault/internal/redact"
	"github.com/frederikb96/tandemvault/internal/testutil"
	"github.com/frederikb96/tandemvault/internal/vault"
)

func init() { vault.ScryptWorkFactor = 10 }

// Every test value carries this marker; no output may contain it.
const mark = "SECRETMARK"

func val(s string) string { return s + "-" + mark }

const totp = "JBSWY3DPEHPK3PXP"

type harness struct {
	t     *testing.T
	dir   string
	cfg   *config.Config
	op    *optest.Fake
	out   bytes.Buffer
	plans []*Plan
}

func newHarness(t *testing.T, withSops bool) *harness {
	t.Helper()
	redact.Reset()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	dir := t.TempDir()
	cfg := &config.Config{
		Path:     filepath.Join(dir, "config.yaml"),
		Mappings: filepath.Join(dir, "mappings.yaml"),
		State:    filepath.Join(dir, "state.json"),
		Vaults: map[string]config.Vault{
			"sealed": {Type: config.TypeAgeDir, Dir: filepath.Join(dir, "sealed"), Identity: filepath.Join(dir, "sealed-identity.age"), Recipient: filepath.Join(dir, "sealed.recipient"), Passphrase: "prompt"},
		},
		OnePassword: config.OnePassword{Account: "test", Backend: config.BackendSDK},
	}
	h := &harness{t: t, dir: dir, cfg: cfg, op: optest.NewFake("Private", "Shared")}
	if withSops {
		testutil.RequireSops(t)
		key, recipient := testutil.AgeKeyFile(t, dir)
		cfg.Vaults["open"] = config.Vault{Type: config.TypeSopsDotenv, Path: filepath.Join(dir, ".sops.env"), AgeKeyFile: key}
		v, _ := vault.Open(cfg, "open", nil)
		if err := v.Init(context.Background(), vault.InitOptions{AgeRecipients: []string{recipient}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.vault("sealed").Init(context.Background(), vault.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) vault(name string) vault.Vault {
	v, err := vault.Open(h.cfg, name, func(context.Context) (string, error) { return "a long test passphrase", nil })
	if err != nil {
		h.t.Fatal(err)
	}
	return v
}

func (h *harness) engine() *Engine {
	h.t.Helper()
	mf, err := mapping.Load(h.cfg.Mappings)
	if err != nil {
		h.t.Fatal(err)
	}
	st, err := mapping.LoadState(h.cfg.State)
	if err != nil {
		h.t.Fatal(err)
	}
	vs := map[string]vault.Vault{}
	for _, n := range h.cfg.VaultNames() {
		vs[n] = h.vault(n)
	}
	return &Engine{Config: h.cfg, Mappings: mf, State: st, Vaults: vs, OP: h.op}
}

func (h *harness) addMapping(m *mapping.Mapping) {
	h.t.Helper()
	mf, _ := mapping.Load(h.cfg.Mappings)
	mf.Mappings = append(mf.Mappings, m)
	if err := mf.Validate(h.cfg); err != nil {
		h.t.Fatal(err)
	}
	if err := mf.Save(h.cfg.Mappings); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) set(vaultName, name, value string) {
	h.t.Helper()
	if err := h.vault(vaultName).Write(context.Background(), name, value); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) get(vaultName, name string) (string, bool) {
	h.t.Helper()
	got, err := h.vault(vaultName).Read(context.Background(), []string{name})
	if err != nil {
		h.t.Fatal(err)
	}
	v, ok := got[name]
	return v, ok
}

// age sets the mtime of a sealed entry, to control which side is newer.
func (h *harness) age(name string, t time.Time) {
	h.t.Helper()
	if err := os.Chtimes(filepath.Join(h.dir, "sealed", name+".age"), t, t); err != nil {
		h.t.Fatal(err)
	}
}

// sync plans and applies, returning the plan. Output goes to h.out.
func (h *harness) sync() *Plan {
	h.t.Helper()
	e := h.engine()
	p, err := e.Plan(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	p.Print(&h.out)
	for _, err := range e.Apply(context.Background(), p) {
		h.out.WriteString("apply error: " + err.Error() + "\n")
	}
	h.plans = append(h.plans, p)
	h.noValues()
	return p
}

func (h *harness) noValues() {
	h.t.Helper()
	if strings.Contains(h.out.String(), mark) || strings.Contains(h.out.String(), totp) {
		h.t.Fatalf("output contains a value:\n%s", h.out.String())
	}
	raw, _ := os.ReadFile(h.cfg.State)
	if strings.Contains(string(raw), mark) {
		h.t.Fatal("state.json contains a value")
	}
	raw, _ = os.ReadFile(h.cfg.Mappings)
	if strings.Contains(string(raw), mark) {
		h.t.Fatal("mappings.yaml contains a value")
	}
}

func no() *bool  { b := false; return &b }
func yes() *bool { b := true; return &b }

func (h *harness) linked(prefix, item string, fields ...onepassword.Field) *mapping.Mapping {
	m := &mapping.Mapping{Vault: "sealed", Prefix: prefix, Item: item, OpVault: h.op.VaultID("Private"), Passkey: no(), Fields: fields}
	h.addMapping(m)
	return m
}

func TestFirstSyncInSyncWritesOnlyState(t *testing.T) {
	h := newHarness(t, false)
	id := h.op.Add("Private", "Example", map[onepassword.Field]string{onepassword.Username: val("alice"), onepassword.Password: val("pw1")})
	h.set("sealed", "EX_USER", val("alice"))
	h.set("sealed", "EX_PASSWORD", val("pw1"))
	h.linked("EX", id, onepassword.Username, onepassword.Password)

	p := h.sync()
	if p.Changes() != 0 || h.op.Writes() != 0 {
		t.Fatalf("changes %d, writes %d\n%s", p.Changes(), h.op.Writes(), h.out.String())
	}
	st, _ := mapping.LoadState(h.cfg.State)
	if st.Mappings["sealed/EX"] == nil || st.Mappings["sealed/EX"].OpVersion != 1 || len(st.Mappings["sealed/EX"].Vault) != 2 {
		t.Fatalf("state not recorded: %+v", st.Mappings["sealed/EX"])
	}
	if !strings.Contains(h.out.String(), "Nothing to do") {
		t.Fatalf("output: %s", h.out.String())
	}
}

func TestVaultChangeGoesTo1PasswordAndOldValueStaysInHistory(t *testing.T) {
	h := newHarness(t, false)
	id := h.op.Add("Private", "Example", map[onepassword.Field]string{onepassword.Password: val("old")})
	h.set("sealed", "EX_PASSWORD", val("old"))
	h.linked("EX", id, onepassword.Password)
	h.sync()

	h.set("sealed", "EX_PASSWORD", val("new"))
	p := h.sync()
	if p.Changes() != 1 {
		t.Fatalf("changes %d\n%s", p.Changes(), h.out.String())
	}
	it := h.op.Item(id)
	if it.Values[onepassword.Password] != val("new") {
		t.Fatal("1Password not updated")
	}
	if it.History[len(it.History)-1][onepassword.Password] != val("old") {
		t.Fatal("old value not in history")
	}
	if !strings.Contains(h.out.String(), "vault → 1Password") || !strings.Contains(h.out.String(), "vault changed") {
		t.Fatalf("plan:\n%s", h.out.String())
	}
	// A third run has nothing to do.
	if p := h.sync(); p.Changes() != 0 {
		t.Fatalf("not idempotent:\n%s", h.out.String())
	}
}

func TestOnePasswordChangeGoesToVault(t *testing.T) {
	h := newHarness(t, false)
	id := h.op.Add("Private", "Example", map[onepassword.Field]string{onepassword.Username: val("alice")})
	h.set("sealed", "EX_USER", val("alice"))
	h.linked("EX", id, onepassword.Username)
	h.sync()

	h.op.Edit(id, map[onepassword.Field]string{onepassword.Username: val("bob")})
	writes := h.op.Writes()
	h.sync()
	if got, _ := h.get("sealed", "EX_USER"); got != val("bob") {
		t.Fatal("vault not updated")
	}
	if h.op.Writes() != writes {
		t.Fatal("1Password written although only 1Password changed")
	}
}

func TestConflictOnePasswordNewerKeepsBothInHistory(t *testing.T) {
	h := newHarness(t, false)
	id := h.op.Add("Private", "Example", map[onepassword.Field]string{onepassword.Password: val("base")})
	h.set("sealed", "EX_PASSWORD", val("base"))
	h.linked("EX", id, onepassword.Password)
	h.sync()

	h.set("sealed", "EX_PASSWORD", val("vaultside"))
	h.age("EX_PASSWORD", h.op.Now().Add(-time.Hour))
	h.op.Edit(id, map[onepassword.Field]string{onepassword.Password: val("opside")})
	before := h.op.Item(id).Version
	h.sync()

	it := h.op.Item(id)
	if it.Version != before+2 {
		t.Fatalf("expected two writes, version %d → %d", before, it.Version)
	}
	if it.Values[onepassword.Password] != val("opside") {
		t.Fatal("1Password lost its newer value")
	}
	if it.History[len(it.History)-1][onepassword.Password] != val("vaultside") {
		t.Fatal("vault's value is not in 1Password's history")
	}
	if got, _ := h.get("sealed", "EX_PASSWORD"); got != val("opside") {
		t.Fatal("vault not updated to the winner")
	}
	if !strings.Contains(h.out.String(), "both changed, 1Password newer") {
		t.Fatalf("plan:\n%s", h.out.String())
	}
}

func TestConflictVaultNewerWins(t *testing.T) {
	h := newHarness(t, false)
	id := h.op.Add("Private", "Example", map[onepassword.Field]string{onepassword.Password: val("base")})
	h.set("sealed", "EX_PASSWORD", val("base"))
	h.linked("EX", id, onepassword.Password)
	h.sync()

	h.op.Edit(id, map[onepassword.Field]string{onepassword.Password: val("opside")})
	h.set("sealed", "EX_PASSWORD", val("vaultside")) // mtime now, far after the fake clock
	before := h.op.Item(id).Version
	h.sync()
	it := h.op.Item(id)
	if it.Values[onepassword.Password] != val("vaultside") || it.Version != before+1 {
		t.Fatalf("vault should win with one write: version %d → %d", before, it.Version)
	}
	if it.History[len(it.History)-1][onepassword.Password] != val("opside") {
		t.Fatal("1Password's own value is not in history")
	}
}

func TestMissingEntriesAreCreatedFrom1Password(t *testing.T) {
	h := newHarness(t, false)
	id := h.op.Add("Private", "Shop", map[onepassword.Field]string{
		onepassword.Username: val("u"), onepassword.Password: val("p"), onepassword.URL: "https://shop.example",
	})
	h.linked("SHOP", id)
	h.sync()
	for name, want := range map[string]string{"SHOP_USER": val("u"), "SHOP_PASSWORD": val("p"), "SHOP_URL": "https://shop.example"} {
		if got, _ := h.get("sealed", name); got != want {
			t.Errorf("%s not created", name)
		}
	}
	if _, ok := h.get("sealed", "SHOP_TOTP_SECRET"); ok {
		t.Error("empty OTP created an entry")
	}
	if !strings.Contains(h.out.String(), "create from 1Password") {
		t.Fatalf("plan:\n%s", h.out.String())
	}
}

func TestEmptyNeverOverwritesPresent(t *testing.T) {
	h := newHarness(t, false)
	id := h.op.Add("Private", "Example", map[onepassword.Field]string{onepassword.Username: val("alice")})
	h.set("sealed", "EX_USER", val("alice"))
	h.set("sealed", "EX_PASSWORD", val("only-in-vault"))
	h.linked("EX", id, onepassword.Username, onepassword.Password)
	h.sync()
	if h.op.Item(id).Values[onepassword.Password] != val("only-in-vault") {
		t.Fatal("empty 1Password field not filled from the vault")
	}
}

func TestOTPFormsCompareEqualAndNonDefaultKeepsURI(t *testing.T) {
	h := newHarness(t, false)
	id := h.op.Add("Private", "Example", map[onepassword.Field]string{onepassword.OTP: "jbsw y3dp ehpk 3pxp"})
	h.set("sealed", "EX_TOTP_SECRET", "otpauth://totp/Example?secret="+totp+"&issuer=Example")
	h.linked("EX", id, onepassword.OTP)
	if p := h.sync(); p.Changes() != 0 {
		t.Fatalf("equal OTP forms planned a change:\n%s", h.out.String())
	}

	id2 := h.op.Add("Private", "Eight", map[onepassword.Field]string{onepassword.OTP: "otpauth://totp/Eight?secret=" + totp + "&digits=8"})
	h.linked("EIGHT", id2, onepassword.OTP)
	h.sync()
	got, _ := h.get("sealed", "EIGHT_TOTP_SECRET")
	if !strings.HasPrefix(got, "otpauth://") || !strings.Contains(got, "digits=8") {
		t.Fatal("non-default OTP parameters dropped")
	}
	if !strings.Contains(h.out.String(), "non-default parameters") {
		t.Fatalf("plan does not flag non-default params:\n%s", h.out.String())
	}

	// vault → 1Password writes an otpauth URI.
	id3 := h.op.Add("Private", "Third", map[onepassword.Field]string{onepassword.Username: val("x")})
	h.set("sealed", "THIRD_TOTP_SECRET", totp)
	h.linked("THIRD", id3, onepassword.OTP)
	h.sync()
	if v := h.op.Item(id3).Values[onepassword.OTP]; !strings.HasPrefix(v, "otpauth://totp/Third?") {
		t.Fatal("vault OTP not written as an otpauth URI")
	}
}

func TestSeveralOTPFieldsAreSkipped(t *testing.T) {
	h := newHarness(t, false)
	id := h.op.Add("Private", "Example", map[onepassword.Field]string{onepassword.OTP: totp})
	h.op.Item(id).OTPFields = 2
	h.set("sealed", "EX_TOTP_SECRET", "AAAABBBBCCCCDDDD")
	h.linked("EX", id, onepassword.OTP)
	h.sync()
	if h.op.Writes() != 0 || !strings.Contains(h.out.String(), "2 one-time password fields") {
		t.Fatalf("writes %d\n%s", h.op.Writes(), h.out.String())
	}
}

func TestCLIBackendEditsOnlyItemsMappedWithoutPasskey(t *testing.T) {
	h := newHarness(t, false)
	h.op.KindName = config.BackendCLI
	ids := map[string]string{}
	for prefix, pk := range map[string]*bool{"KEY": yes(), "UNKNOWN": nil, "NOKEY": no()} {
		ids[prefix] = h.op.Add("Private", prefix, map[onepassword.Field]string{onepassword.Password: val("old")})
		h.set("sealed", prefix+"_PASSWORD", val("old"))
		h.addMapping(&mapping.Mapping{Vault: "sealed", Prefix: prefix, Item: ids[prefix], OpVault: h.op.VaultID("Private"), Passkey: pk, Fields: []onepassword.Field{onepassword.Password}})
	}
	h.sync()
	for prefix := range ids {
		h.set("sealed", prefix+"_PASSWORD", val("new"))
	}
	p := h.sync()
	if p.Changes() != 1 || h.op.Item(ids["NOKEY"]).Values[onepassword.Password] != val("new") {
		t.Fatalf("passkey: false item not written:\n%s", h.out.String())
	}
	for _, prefix := range []string{"KEY", "UNKNOWN"} {
		if h.op.Item(ids[prefix]).Values[onepassword.Password] != val("old") {
			t.Fatalf("%s written by the cli backend", prefix)
		}
	}
	if strings.Count(h.out.String(), "skipped (passkey)") != 2 {
		t.Fatalf("plan:\n%s", h.out.String())
	}
	// The skipped changes stay pending.
	pending, err := h.engine().LocalStatus()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 {
		t.Fatalf("pending %v", pending)
	}
	// The SDK backend edits single fields and keeps passkeys: it writes all of them.
	h.op.KindName = config.BackendSDK
	h.sync()
	for prefix := range ids {
		if h.op.Item(ids[prefix]).Values[onepassword.Password] != val("new") {
			t.Fatalf("%s not written by the sdk backend", prefix)
		}
	}
}

func TestPasskeyConflictMovesLosingVaultValueToTrash(t *testing.T) {
	h := newHarness(t, false)
	h.op.KindName = config.BackendCLI
	id := h.op.Add("Private", "Shop", map[onepassword.Field]string{onepassword.Password: val("base")})
	h.set("sealed", "SHOP_PASSWORD", val("base"))
	h.addMapping(&mapping.Mapping{Vault: "sealed", Prefix: "SHOP", Item: id, OpVault: h.op.VaultID("Private"), Passkey: yes(), Fields: []onepassword.Field{onepassword.Password}})
	h.sync()
	h.set("sealed", "SHOP_PASSWORD", val("vaultside"))
	h.age("SHOP_PASSWORD", h.op.Now().Add(-time.Hour))
	h.op.Edit(id, map[onepassword.Field]string{onepassword.Password: val("opside")})
	h.sync()
	if h.op.Writes() != 0 {
		t.Fatal("passkey item written")
	}
	if got, _ := h.get("sealed", "SHOP_PASSWORD"); got != val("opside") {
		t.Fatal("vault not updated")
	}
	matches, _ := filepath.Glob(filepath.Join(h.dir, "sealed", ".trash", "*", "SHOP_PASSWORD.age"))
	if len(matches) != 1 {
		t.Fatal("losing vault value not in the trash")
	}
}

func TestLinkByTitle(t *testing.T) {
	h := newHarness(t, false)
	id := h.op.Add("Shared", "Unique Site", map[onepassword.Field]string{onepassword.Username: val("u")})
	h.op.Add("Private", "Twice", nil)
	h.op.Add("Shared", "Twice", nil)
	h.addMapping(&mapping.Mapping{Vault: "sealed", Prefix: "UNIQUE", Title: "Unique Site", Passkey: no()})
	h.addMapping(&mapping.Mapping{Vault: "sealed", Prefix: "TWICE", Title: "Twice", Passkey: no()})
	h.addMapping(&mapping.Mapping{Vault: "sealed", Prefix: "NONE", Title: "Does Not Exist", Passkey: no()})
	h.sync()
	mf, _ := mapping.Load(h.cfg.Mappings)
	u, _ := mf.Find("sealed", "UNIQUE")
	if u.Item != id || u.OpVault != h.op.VaultID("Shared") {
		t.Fatalf("not resolved: %+v", u)
	}
	tw, _ := mf.Find("sealed", "TWICE")
	if tw.Resolved() {
		t.Fatal("ambiguous title resolved")
	}
	out := h.out.String()
	if !strings.Contains(out, "several items match") || !strings.Contains(out, "no 1Password item titled") {
		t.Fatalf("plan:\n%s", out)
	}
	if got, _ := h.get("sealed", "UNIQUE_USER"); got != val("u") {
		t.Fatal("linked item not synced in the same run")
	}
}

func TestCreateItemFromVault(t *testing.T) {
	h := newHarness(t, false)
	h.set("sealed", "NEW_USER", val("me"))
	h.set("sealed", "NEW_PASSWORD", val("pw"))
	h.set("sealed", "NEW_TOTP_SECRET", totp)
	h.addMapping(&mapping.Mapping{Vault: "sealed", Prefix: "NEW", Title: "New Site", OpVault: h.op.VaultID("Private"), Create: true})
	h.sync()
	mf, _ := mapping.Load(h.cfg.Mappings)
	m, _ := mf.Find("sealed", "NEW")
	if !m.Resolved() || m.Create || m.Passkey != nil {
		t.Fatalf("mapping after create: %+v", m)
	}
	it := h.op.Item(m.Item)
	if it.Title != "New Site" || it.Values[onepassword.Username] != val("me") || !strings.HasPrefix(it.Values[onepassword.OTP], "otpauth://") {
		t.Fatalf("created item wrong")
	}
	if p := h.sync(); p.Changes() != 0 {
		t.Fatalf("second run not clean:\n%s", h.out.String())
	}
}

func TestUnlinkKeepVaultSoftDeletesItem(t *testing.T) {
	h := newHarness(t, false)
	id := h.op.Add("Private", "Old", map[onepassword.Field]string{onepassword.Username: val("u")})
	h.set("sealed", "OLD_USER", val("u"))
	m := h.linked("OLD", id, onepassword.Username)
	h.sync()
	mf, _ := mapping.Load(h.cfg.Mappings)
	mm, _ := mf.Find("sealed", "OLD")
	mm.Unlink = mapping.KeepVault
	mf.Save(h.cfg.Mappings)
	h.sync()
	if !h.op.Item(id).Deleted {
		t.Fatal("item not deleted")
	}
	mf, _ = mapping.Load(h.cfg.Mappings)
	if len(mf.Mappings) != 0 {
		t.Fatal("mapping not removed")
	}
	if _, ok := h.get("sealed", "OLD_USER"); !ok {
		t.Fatal("vault entry gone")
	}
	st, _ := mapping.LoadState(h.cfg.State)
	if st.Mappings[m.Key()] != nil {
		t.Fatal("state not removed")
	}
}

func TestUnlinkKeepOnePasswordTrashesVault(t *testing.T) {
	h := newHarness(t, true)
	id := h.op.Add("Private", "Old", map[onepassword.Field]string{onepassword.Username: val("u")})
	h.set("open", "OLD_USER", val("u"))
	h.addMapping(&mapping.Mapping{Vault: "open", Prefix: "OLD", Item: id, OpVault: h.op.VaultID("Private"), Passkey: no(), Fields: []onepassword.Field{onepassword.Username}})
	h.sync()
	mf, _ := mapping.Load(h.cfg.Mappings)
	mf.Mappings[0].Unlink = mapping.KeepOnePassword
	mf.Save(h.cfg.Mappings)
	h.sync()
	if h.op.Item(id).Deleted {
		t.Fatal("item deleted")
	}
	if _, ok := h.get("open", "OLD_USER"); ok {
		t.Fatal("vault entry still there")
	}
	if _, err := os.Stat(filepath.Join(h.dir, ".sops.trash.env")); err != nil {
		t.Fatal("trash file missing")
	}
}

func TestOpenVaultSync(t *testing.T) {
	h := newHarness(t, true)
	id := h.op.Add("Private", "Open", map[onepassword.Field]string{onepassword.Password: val("a")})
	h.addMapping(&mapping.Mapping{Vault: "open", Prefix: "OPEN", Item: id, OpVault: h.op.VaultID("Private"), Passkey: no(), Fields: []onepassword.Field{onepassword.Password}})
	h.sync()
	if got, _ := h.get("open", "OPEN_PASSWORD"); got != val("a") {
		t.Fatal("not created in the open vault")
	}
	h.set("open", "OPEN_PASSWORD", val("b"))
	h.sync()
	if h.op.Item(id).Values[onepassword.Password] != val("b") {
		t.Fatal("open vault change not synced")
	}
}

func TestCompareAndSwapAbortsOnConcurrentChange(t *testing.T) {
	h := newHarness(t, false)
	id := h.op.Add("Private", "Example", map[onepassword.Field]string{onepassword.Password: val("old")})
	h.set("sealed", "EX_PASSWORD", val("old"))
	h.linked("EX", id, onepassword.Password)
	h.sync()
	h.set("sealed", "EX_PASSWORD", val("new"))

	// 1Password changes between plan and apply.
	e := h.engine()
	p, err := e.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h.op.Edit(id, map[onepassword.Field]string{onepassword.Username: val("someone")})
	errs := e.Apply(context.Background(), p)
	if len(errs) != 1 || !errors.Is(errs[0], ErrChanged) {
		t.Fatalf("errs %v", errs)
	}
	if h.op.Item(id).Values[onepassword.Password] != val("old") {
		t.Fatal("written despite the change")
	}

	// The vault changes between plan and apply.
	e = h.engine()
	p, _ = e.Plan(context.Background())
	h.set("sealed", "EX_PASSWORD", val("newer"))
	errs = e.Apply(context.Background(), p)
	if len(errs) != 1 || !errors.Is(errs[0], ErrChanged) {
		t.Fatalf("errs %v", errs)
	}

	// 1Password changes during the write itself.
	e = h.engine()
	p, _ = e.Plan(context.Background())
	h.op.BeforeUpdate = func(itemID string) {
		h.op.BeforeUpdate = nil
		h.op.Edit(itemID, map[onepassword.Field]string{onepassword.Username: val("racer")})
	}
	errs = e.Apply(context.Background(), p)
	if len(errs) != 1 || !errors.Is(errs[0], ErrChanged) {
		t.Fatalf("errs %v", errs)
	}
}

func TestConflictCopyBlocks(t *testing.T) {
	h := newHarness(t, false)
	if err := os.WriteFile(filepath.Join(h.dir, "state.sync-conflict-20260101-000000-AAAAAAA.json"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := h.engine().Blockers()
	if err != nil || len(b) != 1 {
		t.Fatalf("blockers %v %v", b, err)
	}
}

func TestDecideTable(t *testing.T) {
	old, newer := time.Unix(100, 0), time.Unix(200, 0)
	cases := []struct {
		name      string
		op, v     side
		firstSync bool
		want      direction
	}{
		{"equal", side{"a", true, true, old}, side{"a", true, true, newer}, false, none},
		{"both empty", side{"", false, true, old}, side{"", false, true, old}, false, none},
		{"op empty", side{"", false, false, old}, side{"a", true, false, old}, false, toOnePassword},
		{"vault missing", side{"a", true, false, old}, side{"", false, false, old}, false, toVault},
		{"vault moved", side{"a", true, false, newer}, side{"b", true, true, old}, false, toOnePassword},
		{"op moved", side{"a", true, true, old}, side{"b", true, false, newer}, false, toVault},
		{"both, vault newer", side{"a", true, true, old}, side{"b", true, true, newer}, false, toOnePassword},
		{"both, op newer", side{"a", true, true, newer}, side{"b", true, true, old}, false, conflictOnePasswordWins},
		{"first, vault newer", side{"a", true, true, old}, side{"b", true, true, newer}, true, toOnePassword},
		{"first, op newer", side{"a", true, true, newer}, side{"b", true, true, old}, true, conflictOnePasswordWins},
	}
	for _, c := range cases {
		if got := decide(onepassword.Password, c.op, c.v, c.firstSync); got.dir != c.want {
			t.Errorf("%s: got %v want %v", c.name, got.dir, c.want)
		}
	}
}
