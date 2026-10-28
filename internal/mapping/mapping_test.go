package mapping

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/frederikb96/tandemvault/internal/config"
	"github.com/frederikb96/tandemvault/internal/onepassword"
)

func cfg() *config.Config {
	return &config.Config{Vaults: map[string]config.Vault{"sealed": {Type: config.TypeAgeDir}, "open": {Type: config.TypeSopsDotenv}}}
}

func b(v bool) *bool { return &v }

const (
	id  = "abcdefghijklmnopqrstuvwxyz"
	vid = "zyxwvutsrqponmlkjihgfedcba"
)

func TestNamesAndFields(t *testing.T) {
	m := &Mapping{Vault: "sealed", Prefix: "WISO", Names: map[onepassword.Field]string{onepassword.Username: "WISO_USERNAME"}, Fields: []onepassword.Field{onepassword.OTP, onepassword.Username}}
	if got := strings.Join(m.EntryNames(), ","); got != "WISO_USERNAME,WISO_TOTP_SECRET" {
		t.Fatalf("entry names %s", got)
	}
	all := &Mapping{Prefix: "X"}
	if got := strings.Join(all.EntryNames(), ","); got != "X_USER,X_PASSWORD,X_TOTP_SECRET,X_URL" {
		t.Fatalf("default names %s", got)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		ms   []*Mapping
		want string
	}{
		{"ok", []*Mapping{{Vault: "sealed", Prefix: "A", Item: id, OpVault: vid, Passkey: b(false)}}, ""},
		{"unknown vault", []*Mapping{{Vault: "nope", Prefix: "A", Title: "t", Passkey: b(false)}}, "not configured"},
		{"bad prefix", []*Mapping{{Vault: "sealed", Prefix: "a-b", Title: "t", Passkey: b(false)}}, "prefix"},
		{"passkey unset", []*Mapping{{Vault: "sealed", Prefix: "A", Title: "t"}}, ""},
		{"vault by title", []*Mapping{{Vault: "sealed", Prefix: "A", Title: "t", OpVault: "Private"}}, "not a 1Password vault ID"},
		{"duplicate key", []*Mapping{{Vault: "sealed", Prefix: "A", Title: "t", Passkey: b(false)}, {Vault: "sealed", Prefix: "A", Title: "u", Passkey: b(false)}}, "defined twice"},
		{"entry clash", []*Mapping{{Vault: "sealed", Prefix: "A", Title: "t", Passkey: b(false), Names: map[onepassword.Field]string{onepassword.Username: "B_USER"}}, {Vault: "sealed", Prefix: "B", Title: "u", Passkey: b(false)}}, "also used"},
		{"same names in different vaults", []*Mapping{{Vault: "sealed", Prefix: "A", Title: "t", Passkey: b(false)}, {Vault: "open", Prefix: "A", Title: "t", Passkey: b(false)}}, ""},
		{"item twice", []*Mapping{{Vault: "sealed", Prefix: "A", Item: id, OpVault: vid, Passkey: b(false)}, {Vault: "open", Prefix: "B", Item: id, OpVault: vid, Passkey: b(false)}}, "also mapped"},
		{"create without vault", []*Mapping{{Vault: "sealed", Prefix: "A", Title: "t", Create: true}}, "create needs"},
		{"bad item", []*Mapping{{Vault: "sealed", Prefix: "A", Item: "nope", OpVault: vid, Passkey: b(false)}}, "not a 1Password item ID"},
		{"bad unlink", []*Mapping{{Vault: "sealed", Prefix: "A", Title: "t", Passkey: b(false), Unlink: "both"}}, "unlink"},
		{"bad field", []*Mapping{{Vault: "sealed", Prefix: "A", Title: "t", Passkey: b(false), Fields: []onepassword.Field{"notes"}}}, "unknown field"},
	}
	for _, c := range cases {
		err := (&File{Mappings: c.ms}).Validate(cfg())
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mappings.yaml")
	empty, err := Load(path)
	if err != nil || len(empty.Mappings) != 0 {
		t.Fatalf("missing file: %v %v", empty, err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := Load(path); err != nil || len(f.Mappings) != 0 {
		t.Fatalf("empty file: %v", err)
	}
	f := &File{Mappings: []*Mapping{{Vault: "sealed", Prefix: "A", Item: id, OpVault: "v", Passkey: b(true), Fields: []onepassword.Field{onepassword.Password}}}}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.Mappings[0].WithoutPasskey() || back.Mappings[0].Passkey == nil || back.Mappings[0].Fields[0] != onepassword.Password {
		t.Fatalf("round trip lost data: %+v", back.Mappings[0])
	}
	if err := os.WriteFile(path, []byte("mappings:\n  - vault: sealed\n    typo: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Mappings["sealed/A"] = &MappingState{Item: id, OpVersion: 3, Vault: map[string]string{"A_USER": "ab"}}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	back, err := LoadState(path)
	if err != nil || back.Mappings["sealed/A"].OpVersion != 3 {
		t.Fatalf("%v %+v", err, back)
	}
	if err := os.WriteFile(path, []byte(`{"version": 9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("unknown state version accepted")
	}
}
