package onepassword

import (
	"context"
	"fmt"

	op "github.com/1password/onepassword-sdk-go"

	"github.com/frederikb96/tandemvault/internal/redact"
)

// sdkAPI is the part of the 1Password SDK the backend uses.
type sdkAPI interface {
	ListVaults(ctx context.Context) ([]op.VaultOverview, error)
	ListItems(ctx context.Context, vaultID string) ([]op.ItemOverview, error)
	GetItem(ctx context.Context, vaultID, itemID string) (op.Item, error)
	PutItem(ctx context.Context, item op.Item) (op.Item, error)
	CreateItem(ctx context.Context, params op.ItemCreateParams) (op.Item, error)
	DeleteItem(ctx context.Context, vaultID, itemID string) error
	Resolve(ctx context.Context, ref string) (string, error)
}

type sdkClient struct{ c *op.Client }

func (s sdkClient) ListVaults(ctx context.Context) ([]op.VaultOverview, error) {
	return s.c.Vaults().List(ctx)
}
func (s sdkClient) ListItems(ctx context.Context, vaultID string) ([]op.ItemOverview, error) {
	return s.c.Items().List(ctx, vaultID)
}
func (s sdkClient) GetItem(ctx context.Context, vaultID, itemID string) (op.Item, error) {
	return s.c.Items().Get(ctx, vaultID, itemID)
}
func (s sdkClient) PutItem(ctx context.Context, item op.Item) (op.Item, error) {
	return s.c.Items().Put(ctx, item)
}
func (s sdkClient) CreateItem(ctx context.Context, params op.ItemCreateParams) (op.Item, error) {
	return s.c.Items().Create(ctx, params)
}
func (s sdkClient) DeleteItem(ctx context.Context, vaultID, itemID string) error {
	return s.c.Items().Delete(ctx, vaultID, itemID)
}
func (s sdkClient) Resolve(ctx context.Context, ref string) (string, error) {
	return s.c.Secrets().Resolve(ctx, ref)
}

// SDK is the backend that talks to the 1Password desktop app.
type SDK struct{ api sdkAPI }

// NewSDK connects to the desktop app for account (its sidebar name or UUID).
// The app asks the user to approve the connection once per process.
func NewSDK(ctx context.Context, account, version string) (*SDK, error) {
	c, err := op.NewClient(ctx,
		op.WithDesktopAppIntegration(account),
		op.WithIntegrationInfo("tandemvault", version),
	)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the 1Password app: %w", err)
	}
	return &SDK{api: sdkClient{c}}, nil
}

func (s *SDK) Kind() string { return "sdk" }

// Built-in Login field IDs.
const (
	sdkUsernameID = "username"
	sdkPasswordID = "password"
)

func fromSDK(it op.Item) Item {
	out := Item{
		ID:        it.ID,
		VaultID:   it.VaultID,
		Title:     it.Title,
		Version:   uint64(it.Version),
		UpdatedAt: it.UpdatedAt.UTC(),
		Values:    map[Field]string{},
	}
	for _, f := range it.Fields {
		switch {
		case f.ID == sdkUsernameID:
			out.Values[Username] = f.Value
		case f.ID == sdkPasswordID:
			out.Values[Password] = f.Value
		case f.FieldType == op.ItemFieldTypeTOTP:
			out.OTPFields++
			out.Values[OTP] = f.Value
		}
	}
	if out.OTPFields > 1 {
		delete(out.Values, OTP)
	}
	if len(it.Websites) > 0 {
		out.Values[URL] = it.Websites[0].URL
	}
	for k, v := range out.Values {
		if v == "" {
			delete(out.Values, k)
			continue
		}
		redact.Register(v)
	}
	return out
}

func (s *SDK) Get(ctx context.Context, vaultID, itemID string) (Item, error) {
	it, err := s.api.GetItem(ctx, vaultID, itemID)
	if err != nil {
		return Item{}, fmt.Errorf("get item %s: %w", itemID, err)
	}
	return fromSDK(it), nil
}

func (s *SDK) Find(ctx context.Context, query, vault string) ([]Candidate, error) {
	vaults, err := s.api.ListVaults(ctx)
	if err != nil {
		return nil, fmt.Errorf("list vaults: %w", err)
	}
	var all []Candidate
	for _, v := range vaults {
		if !vaultMatches(vault, v.ID) {
			continue
		}
		items, err := s.api.ListItems(ctx, v.ID)
		if err != nil {
			return nil, fmt.Errorf("list items in %s: %w", v.Title, err)
		}
		for _, it := range items {
			all = append(all, Candidate{ID: it.ID, VaultID: v.ID, VaultTitle: v.Title, Title: it.Title})
		}
	}
	return MatchCandidates(all, query), nil
}

func (s *SDK) Update(ctx context.Context, vaultID, itemID string, expectVersion uint64, set map[Field]string) (Item, error) {
	it, err := s.api.GetItem(ctx, vaultID, itemID)
	if err != nil {
		return Item{}, fmt.Errorf("get item %s: %w", itemID, err)
	}
	if uint64(it.Version) != expectVersion {
		return Item{}, ErrVersionMismatch
	}
	if err := applySDK(&it, set); err != nil {
		return Item{}, err
	}
	put, err := s.api.PutItem(ctx, it)
	if err != nil {
		return Item{}, fmt.Errorf("update item %s: %w", itemID, err)
	}
	return fromSDK(put), nil
}

// applySDK changes only the requested fields of a full item.
func applySDK(it *op.Item, set map[Field]string) error {
	for field, value := range set {
		redact.Register(value)
		switch field {
		case Username:
			setSDKField(it, sdkUsernameID, "username", op.ItemFieldTypeText, value)
		case Password:
			setSDKField(it, sdkPasswordID, "password", op.ItemFieldTypeConcealed, value)
		case OTP:
			var idx []int
			for i, f := range it.Fields {
				if f.FieldType == op.ItemFieldTypeTOTP {
					idx = append(idx, i)
				}
			}
			switch len(idx) {
			case 0:
				it.Fields = append(it.Fields, newSDKOTPField(it, value))
			case 1:
				it.Fields[idx[0]].Value = value
			default:
				return fmt.Errorf("item %s has %d one-time password fields", it.ID, len(idx))
			}
		case URL:
			if len(it.Websites) == 0 {
				it.Websites = append(it.Websites, op.Website{URL: value, Label: "website", AutofillBehavior: op.AutofillBehaviorAnywhereOnWebsite})
			} else {
				it.Websites[0].URL = value
			}
		default:
			return fmt.Errorf("unknown field %q", field)
		}
	}
	return nil
}

func setSDKField(it *op.Item, id, title string, typ op.ItemFieldType, value string) {
	for i, f := range it.Fields {
		if f.ID == id {
			it.Fields[i].Value = value
			return
		}
	}
	it.Fields = append(it.Fields, op.ItemField{ID: id, Title: title, FieldType: typ, Value: value})
}

// newSDKOTPField places a new one-time password field in the item's first
// section, creating an untitled one when the item has none.
func newSDKOTPField(it *op.Item, value string) op.ItemField {
	if len(it.Sections) == 0 {
		it.Sections = append(it.Sections, op.ItemSection{ID: "otp", Title: ""})
	}
	section := it.Sections[0].ID
	return op.ItemField{ID: "otp", Title: "one-time password", SectionID: &section, FieldType: op.ItemFieldTypeTOTP, Value: value}
}

func (s *SDK) Create(ctx context.Context, vault, title string, values map[Field]string) (Item, error) {
	vaultID, err := s.vaultID(ctx, vault)
	if err != nil {
		return Item{}, err
	}
	params := op.ItemCreateParams{Category: op.ItemCategoryLogin, VaultID: vaultID, Title: title}
	tmp := op.Item{}
	if err := applySDK(&tmp, values); err != nil {
		return Item{}, err
	}
	params.Fields = tmp.Fields
	params.Sections = tmp.Sections
	params.Websites = tmp.Websites
	it, err := s.api.CreateItem(ctx, params)
	if err != nil {
		return Item{}, fmt.Errorf("create item %q: %w", title, err)
	}
	return fromSDK(it), nil
}

func (s *SDK) vaultID(ctx context.Context, id string) (string, error) {
	vaults, err := s.api.ListVaults(ctx)
	if err != nil {
		return "", fmt.Errorf("list vaults: %w", err)
	}
	for _, v := range vaults {
		if v.ID == id {
			return v.ID, nil
		}
	}
	return "", fmt.Errorf("no 1Password vault with ID %q (tandemvault vaults lists them)", id)
}

func (s *SDK) Vaults(ctx context.Context) ([]VaultInfo, error) {
	vaults, err := s.api.ListVaults(ctx)
	if err != nil {
		return nil, fmt.Errorf("list vaults: %w", err)
	}
	out := make([]VaultInfo, 0, len(vaults))
	for _, v := range vaults {
		out = append(out, VaultInfo{ID: v.ID, Title: v.Title, Type: string(v.VaultType)})
	}
	return out, nil
}

func (s *SDK) Delete(ctx context.Context, vaultID, itemID string) error {
	if err := s.api.DeleteItem(ctx, vaultID, itemID); err != nil {
		return fmt.Errorf("delete item %s: %w", itemID, err)
	}
	return nil
}

func (s *SDK) Resolve(ctx context.Context, ref string) (string, error) {
	v, err := s.api.Resolve(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", ref, err)
	}
	redact.Register(v)
	return v, nil
}
