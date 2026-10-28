// Package testutil holds helpers shared by the tests of several packages.
package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// RequireSops skips the test when sops is missing, or fails it when
// TANDEMVAULT_REQUIRE_SOPS is set (as in CI), so a missing binary can never
// turn the sops tests into silent passes there.
func RequireSops(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sops"); err != nil {
		if os.Getenv("TANDEMVAULT_REQUIRE_SOPS") != "" {
			t.Fatal("sops not found on PATH and TANDEMVAULT_REQUIRE_SOPS is set")
		}
		t.Skip("sops not found on PATH")
	}
}

// AgeKeyFile writes a fresh age identity to dir/keys.txt and returns the
// file and its recipient.
func AgeKeyFile(t *testing.T, dir string) (path, recipient string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "keys.txt")
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, id.Recipient().String()
}
