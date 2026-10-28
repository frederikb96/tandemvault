// Package optest provides an in-memory 1Password backend for tests.
package optest

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"sync"
	"time"

	"github.com/frederikb96/tandemvault/internal/onepassword"
)

// Fake is an in-memory onepassword.Backend. Every write bumps the item's
// version and appends the previous values to its history, the way 1Password
// keeps item history.
type Fake struct {
	mu      sync.Mutex
	vaults  map[string]string // id → title
	items   map[string]*FakeItem
	nextID  int
	clock   time.Time
	Secrets map[string]string // op:// reference → value

	// KindName is what Kind reports; "fake" unless set.
	KindName string
	// Calls records each backend call as "<method> <item id>".
	Calls []string
	// BeforeUpdate runs at the start of every Update; tests use it to
	// simulate a concurrent edit.
	BeforeUpdate func(itemID string)
	// DropWrites makes Update bump the version without storing the values,
	// to simulate a write that did not land.
	DropWrites bool
}

// FakeItem is the stored item.
type FakeItem struct {
	onepassword.Item
	Deleted bool
	// History holds every earlier set of values, oldest first.
	History []map[onepassword.Field]string
}

// NewFake returns an empty fake with one vault per given title.
func NewFake(vaultTitles ...string) *Fake {
	f := &Fake{vaults: map[string]string{}, items: map[string]*FakeItem{}, clock: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Secrets: map[string]string{}}
	for i, t := range vaultTitles {
		f.vaults[fmt.Sprintf("vault%021d", i)] = t
	}
	return f
}

// VaultID returns the ID of the vault with the given title.
func (f *Fake) VaultID(title string) string {
	for id, t := range f.vaults {
		if t == title {
			return id
		}
	}
	return ""
}

// Tick advances the fake's clock and returns the new time.
func (f *Fake) Tick() time.Time {
	f.clock = f.clock.Add(time.Minute)
	return f.clock
}

// Now returns the fake's clock.
func (f *Fake) Now() time.Time { return f.clock }

// Add stores an item and returns its ID.
func (f *Fake) Add(vaultTitle, title string, values map[onepassword.Field]string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	id := fmt.Sprintf("item%022d", f.nextID)
	f.items[id] = &FakeItem{Item: onepassword.Item{ID: id, VaultID: f.VaultID(vaultTitle), Title: title, Version: 1, UpdatedAt: f.Tick(), Values: clean(values)}}
	if v, ok := values[onepassword.OTP]; ok && v != "" {
		f.items[id].OTPFields = 1
	}
	return id
}

// Edit changes an item the way a person in the 1Password app would.
func (f *Fake) Edit(id string, set map[onepassword.Field]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.write(f.items[id], set)
}

// Item returns the stored item.
func (f *Fake) Item(id string) *FakeItem {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.items[id]
}

// Items returns every stored item, deleted ones included, sorted by ID.
func (f *Fake) Items() []*FakeItem {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*FakeItem, 0, len(f.items))
	for _, it := range f.items {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (f *Fake) write(it *FakeItem, set map[onepassword.Field]string) {
	it.History = append(it.History, maps.Clone(it.Values))
	vals := maps.Clone(it.Values)
	for k, v := range set {
		vals[k] = v
	}
	it.Values = clean(vals)
	if _, ok := it.Values[onepassword.OTP]; ok && it.OTPFields == 0 {
		it.OTPFields = 1
	}
	it.Version++
	it.UpdatedAt = f.Tick()
}

func clean(in map[onepassword.Field]string) map[onepassword.Field]string {
	out := map[onepassword.Field]string{}
	for k, v := range in {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

func (f *Fake) Kind() string {
	if f.KindName != "" {
		return f.KindName
	}
	return "fake"
}

func (f *Fake) snapshot(it *FakeItem) onepassword.Item {
	out := it.Item
	out.Values = maps.Clone(it.Values)
	if out.OTPFields > 1 {
		delete(out.Values, onepassword.OTP)
	}
	return out
}

func (f *Fake) Vaults(context.Context) ([]onepassword.VaultInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []onepassword.VaultInfo
	for id, t := range f.vaults {
		out = append(out, onepassword.VaultInfo{ID: id, Title: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *Fake) Get(_ context.Context, vaultID, itemID string) (onepassword.Item, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "get "+itemID)
	it, ok := f.items[itemID]
	if !ok || it.Deleted || it.VaultID != vaultID {
		return onepassword.Item{}, fmt.Errorf("item %s not found", itemID)
	}
	return f.snapshot(it), nil
}

func (f *Fake) Find(_ context.Context, query, vault string) ([]onepassword.Candidate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "find "+query)
	var all []onepassword.Candidate
	for _, it := range f.items {
		if it.Deleted || (vault != "" && vault != it.VaultID) {
			continue
		}
		all = append(all, onepassword.Candidate{ID: it.ID, VaultID: it.VaultID, VaultTitle: f.vaults[it.VaultID], Title: it.Title})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return onepassword.MatchCandidates(all, query), nil
}

func (f *Fake) Update(_ context.Context, vaultID, itemID string, expectVersion uint64, set map[onepassword.Field]string) (onepassword.Item, error) {
	if f.BeforeUpdate != nil {
		f.BeforeUpdate(itemID)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "update "+itemID)
	it, ok := f.items[itemID]
	if !ok || it.Deleted || it.VaultID != vaultID {
		return onepassword.Item{}, fmt.Errorf("item %s not found", itemID)
	}
	if it.Version != expectVersion {
		return onepassword.Item{}, onepassword.ErrVersionMismatch
	}
	if f.DropWrites {
		set = nil
	}
	f.write(it, set)
	return f.snapshot(it), nil
}

func (f *Fake) Create(_ context.Context, vault, title string, values map[onepassword.Field]string) (onepassword.Item, error) {
	f.mu.Lock()
	vaultID := ""
	if _, ok := f.vaults[vault]; ok {
		vaultID = vault
	}
	if vaultID == "" {
		f.mu.Unlock()
		return onepassword.Item{}, fmt.Errorf("no vault %q", vault)
	}
	f.Calls = append(f.Calls, "create "+title)
	title2 := f.vaults[vaultID]
	f.mu.Unlock()
	id := f.Add(title2, title, values)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot(f.items[id]), nil
}

func (f *Fake) Delete(_ context.Context, vaultID, itemID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "delete "+itemID)
	it, ok := f.items[itemID]
	if !ok || it.Deleted || it.VaultID != vaultID {
		return fmt.Errorf("item %s not found", itemID)
	}
	it.Deleted = true
	return nil
}

func (f *Fake) Resolve(_ context.Context, ref string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "resolve "+ref)
	v, ok := f.Secrets[ref]
	if !ok {
		return "", fmt.Errorf("no secret at %s", ref)
	}
	return v, nil
}

// Writes counts update, create and delete calls.
func (f *Fake) Writes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.Calls {
		switch {
		case len(c) > 7 && c[:7] == "update ", len(c) > 7 && c[:7] == "create ", len(c) > 7 && c[:7] == "delete ":
			n++
		}
	}
	return n
}
