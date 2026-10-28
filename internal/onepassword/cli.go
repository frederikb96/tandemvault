package onepassword

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/frederikb96/tandemvault/internal/redact"
)

// CLI is the backend that runs the op command. Values reach op only through
// a JSON template on stdin and come back on stdout; nothing secret is ever an
// argument. Editing sends back the complete item, which keeps every other
// field, section, URL and note, but replaces passkeys.
type CLI struct {
	// Bin is the op binary.
	Bin     string
	Account string
}

// NewCLI finds op on PATH.
func NewCLI(account string) (*CLI, error) {
	bin, err := exec.LookPath("op")
	if err != nil {
		return nil, errors.New("op not found on PATH")
	}
	return &CLI{Bin: bin, Account: account}, nil
}

func (c *CLI) Kind() string { return "cli" }

func (c *CLI) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	if c.Account != "" {
		args = append(args, "--account", c.Account)
	}
	cmd := exec.CommandContext(ctx, c.Bin, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("op %s: %s", args[0]+" "+args[1], redact.String(msg))
	}
	return stdout.Bytes(), nil
}

// cliItem is the part of op's item JSON the backend reads. Edits work on the
// raw JSON so that every field op knows about is sent back unchanged.
type cliItem struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Version   uint64    `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Vault     struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"vault"`
	Fields []struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Purpose string `json:"purpose"`
		Value   string `json:"value"`
	} `json:"fields"`
	URLs []struct {
		Href    string `json:"href"`
		Primary bool   `json:"primary"`
	} `json:"urls"`
}

func fromCLI(raw []byte) (Item, error) {
	var ci cliItem
	if err := json.Unmarshal(raw, &ci); err != nil {
		return Item{}, errors.New("op returned an item that does not parse")
	}
	out := Item{ID: ci.ID, VaultID: ci.Vault.ID, Title: ci.Title, Version: ci.Version, UpdatedAt: ci.UpdatedAt.UTC(), Values: map[Field]string{}}
	for _, f := range ci.Fields {
		switch {
		case f.Purpose == "USERNAME":
			out.Values[Username] = f.Value
		case f.Purpose == "PASSWORD":
			out.Values[Password] = f.Value
		case f.Type == "OTP":
			out.OTPFields++
			out.Values[OTP] = f.Value
		}
	}
	if out.OTPFields > 1 {
		delete(out.Values, OTP)
	}
	for i, u := range ci.URLs {
		if u.Primary || (i == 0 && out.Values[URL] == "") {
			out.Values[URL] = u.Href
		}
	}
	for k, v := range out.Values {
		if v == "" {
			delete(out.Values, k)
			continue
		}
		redact.Register(v)
	}
	return out, nil
}

func (c *CLI) getRaw(ctx context.Context, vaultID, itemID string) ([]byte, error) {
	args := []string{"item", "get", itemID, "--reveal", "--format", "json"}
	if vaultID != "" {
		args = append(args, "--vault", vaultID)
	}
	return c.run(ctx, nil, args...)
}

func (c *CLI) Get(ctx context.Context, vaultID, itemID string) (Item, error) {
	raw, err := c.getRaw(ctx, vaultID, itemID)
	if err != nil {
		return Item{}, err
	}
	return fromCLI(raw)
}

func (c *CLI) Vaults(ctx context.Context) ([]VaultInfo, error) {
	raw, err := c.run(ctx, nil, "vault", "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	var list []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, errors.New("op returned a vault list that does not parse")
	}
	out := make([]VaultInfo, 0, len(list))
	for _, v := range list {
		out = append(out, VaultInfo{ID: v.ID, Title: v.Name})
	}
	return out, nil
}

func (c *CLI) Find(ctx context.Context, query, vault string) ([]Candidate, error) {
	args := []string{"item", "list", "--format", "json"}
	if vault != "" {
		args = append(args, "--vault", vault)
	}
	raw, err := c.run(ctx, nil, args...)
	if err != nil {
		return nil, err
	}
	var list []struct {
		ID    string `json:"id"`
		Title string `json:"title"`
		Vault struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"vault"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, errors.New("op returned an item list that does not parse")
	}
	all := make([]Candidate, 0, len(list))
	for _, it := range list {
		all = append(all, Candidate{ID: it.ID, VaultID: it.Vault.ID, VaultTitle: it.Vault.Name, Title: it.Title})
	}
	return MatchCandidates(all, query), nil
}

func (c *CLI) Update(ctx context.Context, vaultID, itemID string, expectVersion uint64, set map[Field]string) (Item, error) {
	raw, err := c.getRaw(ctx, vaultID, itemID)
	if err != nil {
		return Item{}, err
	}
	current, err := fromCLI(raw)
	if err != nil {
		return Item{}, err
	}
	if current.Version != expectVersion {
		return Item{}, ErrVersionMismatch
	}
	template, err := applyCLI(raw, set)
	if err != nil {
		return Item{}, err
	}
	out, err := c.run(ctx, template, "item", "edit", itemID, "--vault", vaultID, "--format", "json")
	if err != nil {
		return Item{}, err
	}
	return fromCLI(out)
}

// applyCLI changes only the requested fields in op's full item JSON.
func applyCLI(raw []byte, set map[Field]string) ([]byte, error) {
	var item map[string]any
	if err := json.Unmarshal(raw, &item); err != nil {
		return nil, errors.New("op returned an item that does not parse")
	}
	fields, _ := item["fields"].([]any)
	for field, value := range set {
		redact.Register(value)
		switch field {
		case Username, Password:
			purpose, typ := "USERNAME", "STRING"
			if field == Password {
				purpose, typ = "PASSWORD", "CONCEALED"
			}
			found := false
			for _, f := range fields {
				if m, ok := f.(map[string]any); ok && m["purpose"] == purpose {
					m["value"] = value
					found = true
				}
			}
			if !found {
				fields = append(fields, map[string]any{"id": string(field), "type": typ, "purpose": purpose, "label": string(field), "value": value})
			}
		case OTP:
			var otps []map[string]any
			for _, f := range fields {
				if m, ok := f.(map[string]any); ok && m["type"] == "OTP" {
					otps = append(otps, m)
				}
			}
			switch len(otps) {
			case 0:
				fields = append(fields, map[string]any{"id": "otp", "type": "OTP", "label": "one-time password", "value": value})
			case 1:
				otps[0]["value"] = value
			default:
				return nil, fmt.Errorf("item has %d one-time password fields", len(otps))
			}
		case URL:
			urls, _ := item["urls"].([]any)
			done := false
			for _, u := range urls {
				if m, ok := u.(map[string]any); ok && m["primary"] == true {
					m["href"] = value
					done = true
				}
			}
			if !done && len(urls) > 0 {
				if m, ok := urls[0].(map[string]any); ok {
					m["href"] = value
					done = true
				}
			}
			if !done {
				urls = append(urls, map[string]any{"href": value, "primary": true, "label": "website"})
			}
			item["urls"] = urls
		default:
			return nil, fmt.Errorf("unknown field %q", field)
		}
	}
	item["fields"] = fields
	return json.Marshal(item)
}

func (c *CLI) Create(ctx context.Context, vault, title string, values map[Field]string) (Item, error) {
	base, err := json.Marshal(map[string]any{"title": title, "category": "LOGIN", "fields": []any{}})
	if err != nil {
		return Item{}, err
	}
	template, err := applyCLI(base, values)
	if err != nil {
		return Item{}, err
	}
	out, err := c.run(ctx, template, "item", "create", "--vault", vault, "--format", "json", "-")
	if err != nil {
		return Item{}, err
	}
	return fromCLI(out)
}

func (c *CLI) Delete(ctx context.Context, vaultID, itemID string) error {
	_, err := c.run(ctx, nil, "item", "delete", itemID, "--vault", vaultID)
	return err
}

func (c *CLI) Resolve(ctx context.Context, ref string) (string, error) {
	out, err := c.run(ctx, nil, "read", ref)
	if err != nil {
		return "", err
	}
	v := strings.TrimSuffix(string(out), "\n")
	redact.Register(v)
	return v, nil
}
