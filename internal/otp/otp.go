// Package otp normalises one-time password secrets so that the different
// ways of writing the same TOTP secret compare equal.
//
// 1Password accepts a raw base32 secret (in any case, with or without spaces)
// as well as an otpauth:// URI. Vault entries usually hold the bare base32
// secret. Two values are the same secret when their canonical forms match.
package otp

import (
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Defaults of RFC 6238 and of every common authenticator app.
const (
	DefaultAlgorithm = "SHA1"
	DefaultDigits    = 6
	DefaultPeriod    = 30
)

// Secret is a parsed TOTP secret.
type Secret struct {
	// Base32 is the secret, uppercase, without spaces or padding.
	Base32    string
	Algorithm string
	Digits    int
	Period    int
	Issuer    string
	Label     string
}

// Parse reads a raw base32 secret or an otpauth://totp URI.
func Parse(value string) (Secret, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Secret{}, errors.New("empty one-time password secret")
	}
	if strings.HasPrefix(strings.ToLower(value), "otpauth://") {
		return parseURI(value)
	}
	b32, err := normaliseBase32(value)
	if err != nil {
		return Secret{}, err
	}
	return Secret{Base32: b32, Algorithm: DefaultAlgorithm, Digits: DefaultDigits, Period: DefaultPeriod}, nil
}

func parseURI(value string) (Secret, error) {
	u, err := url.Parse(value)
	if err != nil {
		return Secret{}, errors.New("one-time password URI does not parse")
	}
	if !strings.EqualFold(u.Host, "totp") {
		return Secret{}, fmt.Errorf("unsupported one-time password type %q (only totp)", u.Host)
	}
	q := u.Query()
	b32, err := normaliseBase32(q.Get("secret"))
	if err != nil {
		return Secret{}, err
	}
	s := Secret{
		Base32:    b32,
		Algorithm: DefaultAlgorithm,
		Digits:    DefaultDigits,
		Period:    DefaultPeriod,
		Issuer:    q.Get("issuer"),
		Label:     strings.TrimPrefix(u.Path, "/"),
	}
	if a := q.Get("algorithm"); a != "" {
		s.Algorithm = strings.ToUpper(a)
	}
	if d := q.Get("digits"); d != "" {
		if s.Digits, err = strconv.Atoi(d); err != nil || s.Digits <= 0 {
			return Secret{}, errors.New("one-time password URI has an invalid digits parameter")
		}
	}
	if p := q.Get("period"); p != "" {
		if s.Period, err = strconv.Atoi(p); err != nil || s.Period <= 0 {
			return Secret{}, errors.New("one-time password URI has an invalid period parameter")
		}
	}
	return s, nil
}

func normaliseBase32(raw string) (string, error) {
	s := strings.ToUpper(raw)
	s = strings.NewReplacer(" ", "", "\t", "", "-", "", "=", "").Replace(s)
	if s == "" {
		return "", errors.New("one-time password secret is empty")
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s); err != nil {
		return "", errors.New("one-time password secret is not valid base32")
	}
	return s, nil
}

// DefaultParams reports whether the secret uses SHA1, 6 digits and 30 seconds.
func (s Secret) DefaultParams() bool {
	return s.Algorithm == DefaultAlgorithm && s.Digits == DefaultDigits && s.Period == DefaultPeriod
}

// Canonical is the comparison key: secret plus the parameters that change the codes.
func (s Secret) Canonical() string {
	return fmt.Sprintf("%s/%s/%d/%d", s.Base32, s.Algorithm, s.Digits, s.Period)
}

// URI renders an otpauth://totp URI. Non-default parameters are always kept.
func (s Secret) URI(label, issuer string) string {
	q := url.Values{}
	q.Set("secret", s.Base32)
	if issuer != "" {
		q.Set("issuer", issuer)
	}
	if !s.DefaultParams() {
		q.Set("algorithm", s.Algorithm)
		q.Set("digits", strconv.Itoa(s.Digits))
		q.Set("period", strconv.Itoa(s.Period))
	}
	return (&url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + label, RawQuery: q.Encode()}).String()
}

// VaultForm is how a secret is stored in a vault: the bare base32 secret when
// the parameters are the defaults, the full URI otherwise, so that no
// parameter is ever dropped.
func (s Secret) VaultForm(label, issuer string) string {
	if s.DefaultParams() {
		return s.Base32
	}
	return s.URI(label, issuer)
}

// Equal reports whether two stored values hold the same secret. Values that
// do not parse are compared as plain strings.
func Equal(a, b string) bool {
	sa, errA := Parse(a)
	sb, errB := Parse(b)
	if errA != nil || errB != nil {
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	return sa.Canonical() == sb.Canonical()
}
