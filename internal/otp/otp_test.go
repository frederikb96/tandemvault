package otp

import (
	"strings"
	"testing"
)

const secret = "JBSWY3DPEHPK3PXP"

func TestEqualAcrossForms(t *testing.T) {
	forms := []string{
		secret,
		"jbsw y3dp ehpk 3pxp",
		"JBSW-Y3DP-EHPK-3PXP",
		"otpauth://totp/Example:alice?secret=" + secret + "&issuer=Example",
		"otpauth://totp/x?secret=jbswy3dpehpk3pxp&algorithm=SHA1&digits=6&period=30",
	}
	for _, a := range forms {
		for _, b := range forms {
			if !Equal(a, b) {
				t.Errorf("Equal(%q, %q) = false", a, b)
			}
		}
	}
}

func TestDifferentParamsDiffer(t *testing.T) {
	if Equal(secret, "otpauth://totp/x?secret="+secret+"&digits=8") {
		t.Fatal("8-digit and 6-digit secrets compare equal")
	}
	if Equal(secret, "AAAABBBBCCCCDDDD") {
		t.Fatal("different secrets compare equal")
	}
}

func TestVaultFormAndURI(t *testing.T) {
	s, err := Parse("otpauth://totp/x?secret=" + strings.ToLower(secret))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.VaultForm("x", "X"); got != secret {
		t.Fatalf("default params: vault form %q, want bare secret", got)
	}
	s, err = Parse("otpauth://totp/x?secret=" + secret + "&algorithm=sha256&digits=8&period=60")
	if err != nil {
		t.Fatal(err)
	}
	vf := s.VaultForm("Label", "Issuer")
	back, err := Parse(vf)
	if err != nil {
		t.Fatal(err)
	}
	if back.Canonical() != s.Canonical() || !strings.HasPrefix(vf, "otpauth://") {
		t.Fatalf("non-default params lost: %q", vf)
	}
	uri := Secret{Base32: secret, Algorithm: DefaultAlgorithm, Digits: DefaultDigits, Period: DefaultPeriod}.URI("Example Site", "Example Site")
	if !strings.HasPrefix(uri, "otpauth://totp/Example%20Site?") || !Equal(uri, secret) {
		t.Fatalf("URI %q", uri)
	}
}

func TestInvalidDoesNotLeakValue(t *testing.T) {
	for _, bad := range []string{"not base32 !!!", "otpauth://hotp/x?secret=" + secret, "otpauth://totp/x?secret=" + secret + "&digits=abc"} {
		_, err := Parse(bad)
		if err == nil {
			t.Fatalf("Parse(%q) succeeded", bad)
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "!!!") {
			t.Fatalf("error carries the value: %v", err)
		}
	}
}
