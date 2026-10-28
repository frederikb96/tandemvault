package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadResolvesPathsAndDefaults(t *testing.T) {
	home, _ := os.UserHomeDir()
	p := write(t, `
onepassword:
  account: my.1password.com
vaults:
  open:
    type: sops-dotenv
    path: ~/vaults/open.env
  sealed:
    type: age-dir
    dir: sealed
    passphrase: prompt
`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Dir(p)
	if c.OnePassword.Backend != BackendSDK {
		t.Errorf("backend default %q", c.OnePassword.Backend)
	}
	if c.Vaults["open"].Path != filepath.Join(home, "vaults/open.env") {
		t.Errorf("~ not expanded: %s", c.Vaults["open"].Path)
	}
	s := c.Vaults["sealed"]
	if s.Dir != filepath.Join(base, "sealed") || s.Identity != filepath.Join(base, "sealed-identity.age") || s.Recipient != filepath.Join(base, "sealed.recipient") {
		t.Errorf("age-dir paths: %+v", s)
	}
	if c.Mappings != filepath.Join(base, "mappings.yaml") || c.State != filepath.Join(base, "state.json") {
		t.Errorf("mappings/state: %s %s", c.Mappings, c.State)
	}
	if _, err := c.PickVault(""); err == nil {
		t.Error("ambiguous vault picked")
	}
	if n, err := c.PickVault("open"); err != nil || n != "open" {
		t.Error("named vault not picked")
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]string{
		"no vaults":      "onepassword: {account: x}\n",
		"unknown key":    "vaults: {a: {type: age-dir, dir: d, passphrase: prompt}}\nextra: 1\n",
		"bad type":       "vaults: {a: {type: zip, path: x}}\n",
		"missing path":   "vaults: {a: {type: sops-dotenv}}\n",
		"missing pass":   "vaults: {a: {type: age-dir, dir: d}}\n",
		"mixed keys":     "vaults: {a: {type: sops-dotenv, path: p, dir: d}}\n",
		"bad backend":    "onepassword: {backend: web}\nvaults: {a: {type: sops-dotenv, path: p}}\n",
		"bad vault name": "vaults: {Open_Vault: {type: sops-dotenv, path: p}}\n",
	}
	for name, body := range cases {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil || !strings.Contains(err.Error(), "no configuration") {
		t.Errorf("missing file: %v", err)
	}
}

func TestNeedsOnePassword(t *testing.T) {
	c, err := Load(write(t, "vaults: {a: {type: sops-dotenv, path: p}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.NeedsOnePassword() == nil {
		t.Fatal("missing account accepted")
	}
}
