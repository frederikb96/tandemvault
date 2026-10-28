package onepassword

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	op "github.com/1password/onepassword-sdk-go"
)

type fakeSDK struct {
	vaults []op.VaultOverview
	items  map[string]op.Item
	puts   []op.Item
}

func (f *fakeSDK) ListVaults(context.Context) ([]op.VaultOverview, error) { return f.vaults, nil }
func (f *fakeSDK) ListItems(_ context.Context, vaultID string) ([]op.ItemOverview, error) {
	var out []op.ItemOverview
	for _, it := range f.items {
		if it.VaultID == vaultID {
			out = append(out, op.ItemOverview{ID: it.ID, Title: it.Title, VaultID: it.VaultID})
		}
	}
	return out, nil
}
func (f *fakeSDK) GetItem(_ context.Context, _, itemID string) (op.Item, error) {
	it, ok := f.items[itemID]
	if !ok {
		return op.Item{}, errors.New("not found")
	}
	return it, nil
}
func (f *fakeSDK) PutItem(_ context.Context, it op.Item) (op.Item, error) {
	it.Version++
	f.items[it.ID] = it
	f.puts = append(f.puts, it)
	return it, nil
}
func (f *fakeSDK) CreateItem(_ context.Context, p op.ItemCreateParams) (op.Item, error) {
	it := op.Item{ID: "newitem00000000000000000000"[:26], Title: p.Title, VaultID: p.VaultID, Category: p.Category, Fields: p.Fields, Sections: p.Sections, Websites: p.Websites, Version: 1}
	f.items[it.ID] = it
	return it, nil
}
func (f *fakeSDK) DeleteItem(context.Context, string, string) error { return nil }
func (f *fakeSDK) Resolve(context.Context, string) (string, error)  { return "resolved", nil }

func sampleSDKItem() op.Item {
	sec := "extra"
	return op.Item{
		ID: "abcdefghijklmnopqrstuvwxyz", Title: "Example", VaultID: "v1", Category: op.ItemCategoryLogin, Version: 7,
		UpdatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600)),
		Notes:     "keep these notes",
		Tags:      []string{"tag"},
		Sections:  []op.ItemSection{{ID: sec, Title: "Extra"}},
		Fields: []op.ItemField{
			{ID: "username", Title: "username", FieldType: op.ItemFieldTypeText, Value: "alice"},
			{ID: "password", Title: "password", FieldType: op.ItemFieldTypeConcealed, Value: "old-password"},
			{ID: "recovery", Title: "Recovery", SectionID: &sec, FieldType: op.ItemFieldTypeConcealed, Value: "recovery-codes"},
			{ID: "otpfield", Title: "one-time password", SectionID: &sec, FieldType: op.ItemFieldTypeTOTP, Value: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"},
		},
		Websites: []op.Website{{URL: "https://a.example", Label: "website"}, {URL: "https://b.example", Label: "second"}},
	}
}

func TestSDKReadAndFieldLevelUpdate(t *testing.T) {
	f := &fakeSDK{items: map[string]op.Item{}}
	it := sampleSDKItem()
	f.items[it.ID] = it
	s := &SDK{api: f}
	got, err := s.Get(context.Background(), "v1", it.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Values[Username] != "alice" || got.Values[Password] != "old-password" || got.Values[URL] != "https://a.example" || got.OTPFields != 1 || got.Version != 7 {
		t.Fatalf("read wrong: %+v", got)
	}
	if got.UpdatedAt.Location() != time.UTC {
		t.Fatal("updated time not normalised to UTC")
	}
	if _, err := s.Update(context.Background(), "v1", it.ID, 6, map[Field]string{Password: "x"}); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("stale version accepted: %v", err)
	}
	if _, err := s.Update(context.Background(), "v1", it.ID, 7, map[Field]string{Password: "new-password", URL: "https://c.example"}); err != nil {
		t.Fatal(err)
	}
	put := f.puts[0]
	if put.Notes != "keep these notes" || len(put.Tags) != 1 || len(put.Sections) != 1 {
		t.Fatal("unrelated item data changed")
	}
	byID := map[string]op.ItemField{}
	for _, fl := range put.Fields {
		byID[fl.ID] = fl
	}
	if byID["password"].Value != "new-password" || byID["username"].Value != "alice" || byID["recovery"].Value != "recovery-codes" || byID["otpfield"].Value != it.Fields[3].Value {
		t.Fatal("fields other than the requested one changed")
	}
	if put.Websites[0].URL != "https://c.example" || put.Websites[0].Label != "website" || put.Websites[1].URL != "https://b.example" {
		t.Fatal("primary URL update touched label or other URLs")
	}
}

func TestSDKAddsOTPFieldInSection(t *testing.T) {
	it := op.Item{ID: "abcdefghijklmnopqrstuvwxyz", VaultID: "v1"}
	if err := applySDK(&it, map[Field]string{OTP: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", Username: "u"}); err != nil {
		t.Fatal(err)
	}
	var otpField *op.ItemField
	for i := range it.Fields {
		if it.Fields[i].FieldType == op.ItemFieldTypeTOTP {
			otpField = &it.Fields[i]
		}
	}
	if otpField == nil || otpField.SectionID == nil || len(it.Sections) != 1 || *otpField.SectionID != it.Sections[0].ID {
		t.Fatalf("OTP field not placed in a section: %+v", it)
	}
	two := sampleSDKItem()
	two.Fields = append(two.Fields, op.ItemField{ID: "otp2", FieldType: op.ItemFieldTypeTOTP})
	if err := applySDK(&two, map[Field]string{OTP: "x"}); err == nil {
		t.Fatal("wrote into an item with two OTP fields")
	}
}

func TestSDKFind(t *testing.T) {
	f := &fakeSDK{vaults: []op.VaultOverview{{ID: "v1", Title: "Private"}, {ID: "v2", Title: "Shared"}}, items: map[string]op.Item{
		"aaaaaaaaaaaaaaaaaaaaaaaaaa": {ID: "aaaaaaaaaaaaaaaaaaaaaaaaaa", Title: "Bahn", VaultID: "v1"},
		"bbbbbbbbbbbbbbbbbbbbbbbbbb": {ID: "bbbbbbbbbbbbbbbbbbbbbbbbbb", Title: "bahn", VaultID: "v2"},
		"cccccccccccccccccccccccccc": {ID: "cccccccccccccccccccccccccc", Title: "Other", VaultID: "v2"},
	}}
	s := &SDK{api: f}
	c, _ := s.Find(context.Background(), "Bahn", "")
	if len(c) != 1 || c[0].ID != "aaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("exact match first: %+v", c)
	}
	c, _ = s.Find(context.Background(), "BAHN", "")
	if len(c) != 2 {
		t.Fatalf("case-insensitive fallback: %+v", c)
	}
	c, _ = s.Find(context.Background(), "bahn", "v2")
	if len(c) != 1 || c[0].VaultTitle != "Shared" {
		t.Fatalf("vault filter: %+v", c)
	}
	if c, _ = s.Find(context.Background(), "bahn", "Shared"); len(c) != 0 {
		t.Fatalf("vault matched by title: %+v", c)
	}
	if _, err := s.Create(context.Background(), "Private", "x", nil); err == nil {
		t.Fatal("create accepted a vault title")
	}
	c, _ = s.Find(context.Background(), "cccccccccccccccccccccccccc", "")
	if len(c) != 1 {
		t.Fatalf("by ID: %+v", c)
	}
}

// fakeOp writes a script standing in for op: item get prints a fixed item,
// item edit and item create record their stdin and print it back with a
// bumped version.
func fakeOp(t *testing.T, item string) (bin, dir string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "item.json"), []byte(item), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
dir="$(dirname "$0")"
echo "$@" >> "$dir/argv.log"
case "$1 $2" in
  "item get") cat "$dir/item.json" ;;
  "item edit"|"item create") cat > "$dir/stdin.json"; sed 's/"version": *[0-9]*/"version": 99/' "$dir/stdin.json" ;;
  "item delete") ;;
  "read "*) printf 'from-op\n' ;;
  *) echo "unexpected $*" >&2; exit 1 ;;
esac
`
	bin = filepath.Join(dir, "op")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, dir
}

const cliItemJSON = `{
  "id": "abcdefghijklmnopqrstuvwxyz", "title": "Example", "version": 4,
  "updated_at": "2026-01-02T03:04:05+01:00",
  "vault": {"id": "v1", "name": "Private"},
  "category": "LOGIN", "tags": ["t"],
  "fields": [
    {"id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username", "value": "alice"},
    {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": "old-password", "password_details": {"strength": "FAIR"}},
    {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": "keep these notes"},
    {"id": "custom", "type": "CONCEALED", "label": "Recovery", "section": {"id": "s1", "label": "Extra"}, "value": "recovery-codes"}
  ],
  "urls": [{"label": "website", "primary": true, "href": "https://a.example"}, {"label": "second", "href": "https://b.example"}]
}`

func TestCLIUpdateSendsFullItemOnStdin(t *testing.T) {
	bin, dir := fakeOp(t, cliItemJSON)
	c := &CLI{Bin: bin, Account: "acct"}
	got, err := c.Get(context.Background(), "v1", "abcdefghijklmnopqrstuvwxyz")
	if err != nil {
		t.Fatal(err)
	}
	if got.Values[Username] != "alice" || got.Values[URL] != "https://a.example" || got.Version != 4 || got.UpdatedAt.Location() != time.UTC {
		t.Fatalf("read wrong: %+v", got)
	}
	if _, err := c.Update(context.Background(), "v1", got.ID, 3, map[Field]string{Password: "x"}); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("stale version accepted: %v", err)
	}
	out, err := c.Update(context.Background(), "v1", got.ID, 4, map[Field]string{Password: "new-password", OTP: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != 99 {
		t.Fatal("result not parsed from op's output")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "stdin.json"))
	var sent map[string]any
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatal(err)
	}
	fields := sent["fields"].([]any)
	values := map[string]string{}
	for _, f := range fields {
		m := f.(map[string]any)
		values[m["id"].(string)] = m["value"].(string)
		if m["id"] == "password" && m["password_details"] == nil {
			t.Error("unknown field attributes dropped")
		}
	}
	if values["password"] != "new-password" || values["username"] != "alice" || values["notesPlain"] != "keep these notes" || values["custom"] != "recovery-codes" || values["otp"] == "" {
		t.Fatalf("template fields wrong: %v", values)
	}
	if len(sent["urls"].([]any)) != 2 || sent["tags"] == nil {
		t.Fatal("template dropped URLs or tags")
	}
	argv, _ := os.ReadFile(filepath.Join(dir, "argv.log"))
	if strings.Contains(string(argv), "new-password") || strings.Contains(string(argv), "JBSWY3DPEHPK3PXP") {
		t.Fatal("a value reached op's argv")
	}
	if !strings.Contains(string(argv), "--account acct") {
		t.Fatal("account not passed")
	}
}

func TestCLICreateAndResolve(t *testing.T) {
	bin, dir := fakeOp(t, cliItemJSON)
	c := &CLI{Bin: bin}
	if _, err := c.Create(context.Background(), "Private", "New", map[Field]string{Username: "u", Password: "p-secret", URL: "https://n.example"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "stdin.json"))
	if !strings.Contains(string(raw), `"category":"LOGIN"`) || !strings.Contains(string(raw), "p-secret") {
		t.Fatalf("create template: %s", raw)
	}
	argv, _ := os.ReadFile(filepath.Join(dir, "argv.log"))
	if strings.Contains(string(argv), "p-secret") || !strings.Contains(string(argv), "item create --vault Private --format json -") {
		t.Fatalf("argv: %s", argv)
	}
	v, err := c.Resolve(context.Background(), "op://Private/x/password")
	if err != nil || v != "from-op" {
		t.Fatalf("resolve %q %v", v, err)
	}
}

func TestIsID(t *testing.T) {
	if !IsID("a1b2c3d4e5f6g7h8i9j0k1l2m3") || IsID("Example Shop") || IsID("A1B2C3D4E5F6G7H8I9J0K1L2M3") {
		t.Fatal("IsItemID wrong")
	}
}
