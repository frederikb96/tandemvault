package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/frederikb96/tandemvault/internal/config"
	"github.com/frederikb96/tandemvault/internal/mapping"
	"github.com/frederikb96/tandemvault/internal/onepassword"
	"github.com/frederikb96/tandemvault/internal/otp"
	"github.com/frederikb96/tandemvault/internal/vault"
)

// Engine holds everything a sync run works on.
type Engine struct {
	Config   *config.Config
	Mappings *mapping.File
	State    *mapping.State
	Vaults   map[string]vault.Vault
	OP       onepassword.Backend
	// Now stamps trash entries. Defaults to time.Now.
	Now func() time.Time
}

// kind of work planned for one mapping.
type kind int

const (
	// kindNone: nothing to apply, only skipped lines.
	kindNone kind = iota
	kindSync
	kindCreate
	kindUnlinkKeepVault
	kindUnlinkKeepOP
	kindDropMapping
	kindReturn
	kindRetire
)

// Line is one row of the printed plan. It never holds a value.
type Line struct {
	Label  string
	What   string
	Action string
	Reason string
	Skip   bool
}

// ItemPlan is the work planned for one mapping.
type ItemPlan struct {
	M     *mapping.Mapping
	kind  kind
	Lines []Line
	Err   error

	// Resolved item, and whether resolving it was part of this plan.
	itemID, opVaultID string
	link              bool
	item              onepassword.Item
	entries           map[string]vault.Entry

	opPre       map[onepassword.Field]string
	opWrites    map[onepassword.Field]string
	vaultTrash  []string
	vaultWrites map[string]string
	createVals  map[onepassword.Field]string
	// skipped entry names keep their recorded fingerprint, so the change stays pending.
	skipped map[string]bool
	// expect holds, per field, the vault value 1Password must hold once the
	// planned writes are done. Fields where 1Password's newer value wins are absent.
	expect map[onepassword.Field]string
	// remove lists the vault entries a return or retire deletes.
	remove []string
}

// Changes counts the planned changes.
func (p *ItemPlan) Changes() int {
	n := 0
	for _, l := range p.Lines {
		if !l.Skip {
			n++
		}
	}
	return n
}

// Plan is the whole planned run.
type Plan struct {
	Items []*ItemPlan
}

// Changes counts the planned changes over all items.
func (p *Plan) Changes() int {
	n := 0
	for _, it := range p.Items {
		n += it.Changes()
	}
	return n
}

// Errors lists the per-item planning errors.
func (p *Plan) Errors() []error {
	var out []error
	for _, it := range p.Items {
		if it.Err != nil {
			out = append(out, fmt.Errorf("%s: %w", it.M.Key(), it.Err))
		}
	}
	return out
}

// Print writes the plan. Only names, directions and reasons are printed.
func (p *Plan) Print(w io.Writer) {
	var rows []Line
	items := 0
	for _, it := range p.Items {
		if it.Changes() > 0 {
			items++
		}
		rows = append(rows, it.Lines...)
		if it.Err != nil {
			rows = append(rows, Line{Label: label(it.M, it.item.Title), What: "error", Action: it.Err.Error(), Skip: true})
		}
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "Nothing to do, everything is in sync.")
		return
	}
	fmt.Fprintf(w, "Plan: %d change(s) in %d item(s)\n", p.Changes(), items)
	widths := [3]int{}
	for _, r := range rows {
		widths[0] = max(widths[0], len(r.Label))
		widths[1] = max(widths[1], len(r.What))
		widths[2] = max(widths[2], len(r.Action))
	}
	for _, r := range rows {
		line := fmt.Sprintf("  %-*s  %-*s  %-*s", widths[0], r.Label, widths[1], r.What, widths[2], r.Action)
		if r.Reason != "" {
			line += "  (" + r.Reason + ")"
		}
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
}

func label(m *mapping.Mapping, title string) string {
	if title == "" {
		title = m.Title
	}
	key := m.Key()
	if m.Lease {
		key += ", lease"
	}
	if title == "" {
		return "[" + key + "]"
	}
	return title + " [" + key + "]"
}

// Blockers lists file-sync conflict copies of anything the run reads or
// writes. A sync refuses to run while one exists: one of the two copies holds
// a change the other lacks, and only a person can tell which.
func (e *Engine) Blockers() ([]string, error) {
	var out []string
	for _, name := range e.Config.VaultNames() {
		v, ok := e.Vaults[name]
		if !ok {
			continue
		}
		c, err := v.ConflictCopies()
		if err != nil {
			return nil, err
		}
		out = append(out, c...)
	}
	for _, p := range []string{e.Config.Mappings, e.Config.State, e.Config.Path} {
		c, err := vault.ConflictCopiesOf(p)
		if err != nil {
			return nil, err
		}
		out = append(out, c...)
	}
	sort.Strings(out)
	return out, nil
}

// opWritable reports whether the mapping's 1Password item may be edited.
// The SDK edits single fields and keeps passkeys. The CLI backend sends the
// whole item back, which replaces passkeys, and neither backend can see
// whether an item has one, so the CLI backend edits only items mapped with
// passkey: false.
func (e *Engine) opWritable(m *mapping.Mapping) bool {
	return e.OP.Kind() != config.BackendCLI || m.WithoutPasskey()
}

// Plan reads both sides of every mapping and decides what to do.
func (e *Engine) Plan(ctx context.Context) (*Plan, error) {
	if err := e.Mappings.Validate(e.Config); err != nil {
		return nil, err
	}
	plan := &Plan{}
	for _, m := range e.Mappings.Mappings {
		ip := &ItemPlan{M: m, skipped: map[string]bool{}}
		ip.Err = e.planOne(ctx, ip)
		plan.Items = append(plan.Items, ip)
	}
	return plan, nil
}

func (e *Engine) planOne(ctx context.Context, ip *ItemPlan) error {
	m := ip.M
	v := e.Vaults[m.Vault]
	switch {
	case m.Unlink == mapping.Return || m.Unlink == mapping.Retire:
		return e.planReturn(ctx, ip, v)
	case m.Unlink != "":
		return e.planUnlink(ctx, ip, v)
	case m.Create:
		return e.planCreate(ctx, ip, v)
	}
	ip.itemID, ip.opVaultID = m.Item, m.OpVault
	if !m.Resolved() {
		cands, err := e.OP.Find(ctx, m.Title, m.OpVault)
		if err != nil {
			return err
		}
		switch len(cands) {
		case 0:
			ip.Lines = append(ip.Lines, Line{Label: label(m, ""), What: "link", Action: fmt.Sprintf("skipped, no 1Password item title matches %q", m.Title), Skip: true})
			return nil
		case 1:
			c := cands[0]
			ip.itemID, ip.opVaultID, ip.link = c.ID, c.VaultID, true
			line := Line{Label: label(m, c.Title), What: "link", Action: fmt.Sprintf("→ %s (vault %s)", c.ID, c.VaultTitle)}
			if c.Match != onepassword.MatchID && c.Match != onepassword.MatchExact {
				line.Reason = fmt.Sprintf("best match for %q: %s", m.Title, c.Match)
			}
			ip.Lines = append(ip.Lines, line)
		default:
			var ids []string
			for _, c := range cands {
				ids = append(ids, fmt.Sprintf("%s %q in %s", c.ID, c.Title, c.VaultTitle))
			}
			ip.Lines = append(ip.Lines, Line{Label: label(m, ""), What: "link", Action: "skipped, several items match (" + cands[0].Match + "): " + strings.Join(ids, ", ") + "; link by item ID", Skip: true})
			return nil
		}
	}
	return e.planSync(ctx, ip, v)
}

func (e *Engine) planUnlink(ctx context.Context, ip *ItemPlan, v vault.Vault) error {
	m := ip.M
	switch m.Unlink {
	case mapping.KeepVault:
		if !m.Resolved() {
			ip.kind = kindDropMapping
			ip.Lines = append(ip.Lines, Line{Label: label(m, ""), What: "break sync", Action: "keep vault, drop the unresolved mapping"})
			return nil
		}
		item, err := e.OP.Get(ctx, m.OpVault, m.Item)
		if err != nil {
			return err
		}
		ip.item = item
		ip.kind = kindUnlinkKeepVault
		ip.Lines = append(ip.Lines, Line{Label: label(m, item.Title), What: "break sync", Action: "keep vault; 1Password item → Recently Deleted"})
	case mapping.KeepOnePassword:
		entries, err := v.Entries(m.EntryNames())
		if err != nil {
			return err
		}
		var present []string
		for _, n := range m.EntryNames() {
			if entries[n].Present {
				present = append(present, n)
			}
		}
		ip.kind = kindUnlinkKeepOP
		ip.vaultTrash = present
		action := "keep 1Password; nothing in the vault to move"
		if len(present) > 0 {
			action = "keep 1Password; vault " + strings.Join(present, ", ") + " → vault trash"
		}
		ip.Lines = append(ip.Lines, Line{Label: label(m, ""), What: "break sync", Action: action})
	}
	return nil
}

// planReturn plans a return or a retire: the usual sync towards 1Password,
// no vault writes, and the vault entries deleted once 1Password is checked
// to hold their values.
func (e *Engine) planReturn(ctx context.Context, ip *ItemPlan, v vault.Vault) error {
	m := ip.M
	ip.itemID, ip.opVaultID = m.Item, m.OpVault
	if err := e.planSync(ctx, ip, v); err != nil {
		return err
	}
	lbl := label(m, ip.item.Title)
	if len(ip.skipped) > 0 || len(ip.vaultTrash) > 0 {
		var names []string
		for n := range ip.skipped {
			names = append(names, n)
		}
		names = append(names, ip.vaultTrash...)
		sort.Strings(names)
		ip.kind, ip.opPre, ip.opWrites, ip.vaultWrites, ip.vaultTrash = kindNone, nil, nil, nil, nil
		ip.Lines = append(ip.Lines, Line{Label: lbl, What: m.Unlink, Action: "skipped", Reason: "1Password cannot take the vault's value of " + strings.Join(names, ", ") + ", so the vault copy stays", Skip: true})
		return nil
	}
	// The vault copy goes away, so nothing is written to it. A conflict that
	// 1Password wins still puts the vault's value into the item's history.
	ip.vaultWrites = nil
	kept := ip.Lines[:0]
	for _, l := range ip.Lines {
		switch {
		case l.Action == "1Password → vault" && strings.Contains(l.Reason, "1Password history"):
			l.Action = "vault value → 1Password history"
		case l.Action == "1Password → vault" || l.Action == "create from 1Password":
			continue
		}
		kept = append(kept, l)
	}
	ip.Lines = kept
	for _, n := range m.EntryNames() {
		if ip.entries[n].Present {
			ip.remove = append(ip.remove, n)
		}
	}
	what := "vault " + strings.Join(ip.remove, ", ") + " deleted once 1Password is checked to hold them"
	if len(ip.remove) == 0 {
		what = "nothing in the vault to delete"
	}
	ip.kind = kindReturn
	if m.Unlink == mapping.Retire {
		ip.kind = kindRetire
		what += "; 1Password item → Recently Deleted"
	}
	ip.Lines = append(ip.Lines, Line{Label: lbl, What: m.Unlink, Action: what})
	return nil
}

func (e *Engine) planCreate(ctx context.Context, ip *ItemPlan, v vault.Vault) error {
	m := ip.M
	vals, err := v.Read(ctx, m.EntryNames())
	if err != nil {
		return err
	}
	ip.createVals = map[onepassword.Field]string{}
	var from []string
	for _, f := range m.SyncedFields() {
		val, ok := vals[m.NameFor(f)]
		if !ok || val == "" {
			continue
		}
		if f == onepassword.OTP {
			s, err := otp.Parse(val)
			if err != nil {
				ip.Lines = append(ip.Lines, Line{Label: label(m, m.Title), What: m.NameFor(f), Action: "skipped", Reason: "not a valid one-time password secret", Skip: true})
				continue
			}
			val = s.URI(m.Title, m.Title)
		}
		ip.createVals[f] = val
		from = append(from, m.NameFor(f))
	}
	if len(from) == 0 {
		ip.Lines = append(ip.Lines, Line{Label: label(m, m.Title), What: "create", Action: "skipped, no vault entry to create the item from", Skip: true})
		return nil
	}
	ip.entries, err = v.Entries(m.EntryNames())
	if err != nil {
		return err
	}
	ip.kind = kindCreate
	ip.Lines = append(ip.Lines, Line{Label: label(m, m.Title), What: "create", Action: fmt.Sprintf("new 1Password item in %s from %s", m.OpVault, strings.Join(from, ", "))})
	return nil
}

func (e *Engine) planSync(ctx context.Context, ip *ItemPlan, v vault.Vault) error {
	m := ip.M
	item, err := e.OP.Get(ctx, ip.opVaultID, ip.itemID)
	if err != nil {
		return err
	}
	ip.item = item
	ip.kind = kindSync
	names := m.EntryNames()
	if ip.entries, err = v.Entries(names); err != nil {
		return err
	}
	vals, err := v.Read(ctx, names)
	if err != nil {
		return err
	}
	st := e.State.Mappings[m.Key()]
	if st != nil && st.Item != ip.itemID {
		st = nil
	}
	firstSync := st == nil
	opMoved := firstSync || st.OpVersion != item.Version
	writable := e.opWritable(m)
	lbl := label(m, item.Title)

	ip.opPre, ip.opWrites, ip.vaultWrites = map[onepassword.Field]string{}, map[onepassword.Field]string{}, map[string]string{}
	ip.expect = map[onepassword.Field]string{}
	for _, f := range m.SyncedFields() {
		name := m.NameFor(f)
		if f == onepassword.OTP && item.OTPFields > 1 {
			ip.Lines = append(ip.Lines, Line{Label: lbl, What: string(f), Action: "skipped", Reason: fmt.Sprintf("the item has %d one-time password fields", item.OTPFields), Skip: true})
			ip.skipped[name] = true
			continue
		}
		entry := ip.entries[name]
		vMoved := firstSync
		if !firstSync {
			prev, ok := st.Vault[name]
			vMoved = !ok || prev != entry.Fingerprint
		}
		opVal, opOK := item.Values[f]
		vVal, vOK := vals[name]
		d := decide(f,
			side{value: opVal, present: opOK, moved: opMoved, time: item.UpdatedAt},
			side{value: vVal, present: vOK, moved: vMoved, time: entry.ModTime},
			firstSync)
		if vOK && (d.dir == none || d.dir == toOnePassword) {
			ip.expect[f] = vVal
		}
		if d.dir == none {
			continue
		}
		// Convert values between the two sides' OTP forms.
		toOP, toV := vVal, opVal
		reason := d.reason
		if f == onepassword.OTP {
			if d.dir == toOnePassword || d.dir == conflictOnePasswordWins {
				s, err := otp.Parse(vVal)
				if err != nil {
					ip.Lines = append(ip.Lines, Line{Label: lbl, What: name, Action: "skipped", Reason: "vault value is not a valid one-time password secret", Skip: true})
					ip.skipped[name] = true
					continue
				}
				toOP = s.URI(orDefault(s.Label, item.Title), orDefault(s.Issuer, item.Title))
			}
			if d.dir == toVault || d.dir == conflictOnePasswordWins {
				s, err := otp.Parse(opVal)
				if err != nil {
					ip.Lines = append(ip.Lines, Line{Label: lbl, What: name, Action: "skipped", Reason: "1Password value is not a valid one-time password secret", Skip: true})
					ip.skipped[name] = true
					continue
				}
				toV = s.VaultForm(orDefault(s.Label, item.Title), orDefault(s.Issuer, item.Title))
				if !s.DefaultParams() {
					reason += "; non-default parameters, stored as otpauth URI"
				}
			}
		}
		switch d.dir {
		case toVault:
			ip.vaultWrites[name] = toV
			action := "1Password → vault"
			if !vOK {
				action = "create from 1Password"
			}
			ip.Lines = append(ip.Lines, Line{Label: lbl, What: name, Action: action, Reason: reason})
		case toOnePassword:
			if !writable {
				ip.Lines = append(ip.Lines, Line{Label: lbl, What: string(f), Action: "skipped (passkey)", Reason: reason + "; the cli backend edits only items mapped with passkey: false", Skip: true})
				ip.skipped[name] = true
				continue
			}
			ip.opWrites[f] = toOP
			ip.Lines = append(ip.Lines, Line{Label: lbl, What: string(f), Action: "vault → 1Password", Reason: reason})
		case conflictOnePasswordWins:
			ip.vaultWrites[name] = toV
			if writable {
				ip.opPre[f] = toOP
				ip.opWrites[f] = opVal
				reason += "; vault value kept in 1Password history"
			} else {
				ip.vaultTrash = append(ip.vaultTrash, name)
				reason += "; vault value moved to vault trash (passkey, cli backend)"
			}
			ip.Lines = append(ip.Lines, Line{Label: lbl, What: name, Action: "1Password → vault", Reason: reason})
		}
	}
	return nil
}

func orDefault(s, d string) string {
	if s != "" {
		return s
	}
	return d
}

// ErrChanged means a side changed between planning and applying.
var ErrChanged = errors.New("changed since the plan was made, run sync again")

// Apply carries out the plan and records the state of every item it read,
// changed or not. It stops an item at its first error and moves on to the
// next; the returned errors name each failed item.
func (e *Engine) Apply(ctx context.Context, plan *Plan) []error {
	var errs []error
	for _, ip := range plan.Items {
		// An in-sync item still goes through applyOne: its state gets recorded.
		if ip.Err != nil || ip.kind == kindNone {
			continue
		}
		if err := e.applyOne(ctx, ip); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ip.M.Key(), err))
		}
	}
	return errs
}

func (e *Engine) stamp() string {
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	return now().UTC().Format("20060102T150405Z")
}

func (e *Engine) save() error {
	if err := e.Mappings.Save(e.Config.Mappings); err != nil {
		return err
	}
	return e.State.Save(e.Config.State)
}

func (e *Engine) applyOne(ctx context.Context, ip *ItemPlan) error {
	m := ip.M
	v := e.Vaults[m.Vault]
	switch ip.kind {
	case kindDropMapping:
		e.Mappings.Remove(m)
		delete(e.State.Mappings, m.Key())
		return e.save()
	case kindUnlinkKeepVault:
		if err := e.OP.Delete(ctx, m.OpVault, m.Item); err != nil {
			return err
		}
		e.Mappings.Remove(m)
		delete(e.State.Mappings, m.Key())
		return e.save()
	case kindUnlinkKeepOP:
		if len(ip.vaultTrash) > 0 {
			if err := v.Trash(ctx, ip.vaultTrash, e.stamp()); err != nil {
				return err
			}
		}
		e.Mappings.Remove(m)
		delete(e.State.Mappings, m.Key())
		return e.save()
	case kindCreate:
		if err := e.checkEntries(v, ip); err != nil {
			return err
		}
		item, err := e.OP.Create(ctx, m.OpVault, m.Title, ip.createVals)
		if err != nil {
			return err
		}
		m.Item, m.OpVault, m.Create = item.ID, item.VaultID, false
		return e.record(m, item, v, nil)
	}

	// kindSync, kindReturn, kindRetire: compare-and-swap against what the plan saw.
	current, err := e.OP.Get(ctx, ip.opVaultID, ip.itemID)
	if err != nil {
		return err
	}
	if current.Version != ip.item.Version {
		return ErrChanged
	}
	if err := e.checkEntries(v, ip); err != nil {
		return err
	}
	if ip.link {
		m.Item, m.OpVault, m.Title = ip.itemID, ip.opVaultID, current.Title
		if err := e.Mappings.Save(e.Config.Mappings); err != nil {
			return err
		}
	}
	item := current
	if len(ip.opPre) > 0 {
		if item, err = e.OP.Update(ctx, ip.opVaultID, ip.itemID, item.Version, ip.opPre); err != nil {
			return mismatch(err)
		}
	}
	if len(ip.opWrites) > 0 {
		if item, err = e.OP.Update(ctx, ip.opVaultID, ip.itemID, item.Version, ip.opWrites); err != nil {
			return mismatch(err)
		}
	}
	if ip.kind == kindReturn || ip.kind == kindRetire {
		return e.finishReturn(ctx, ip, v)
	}
	if len(ip.vaultTrash) > 0 {
		if err := v.Trash(ctx, ip.vaultTrash, e.stamp()); err != nil {
			return err
		}
	}
	for _, name := range sortedKeys(ip.vaultWrites) {
		if err := v.Write(ctx, name, ip.vaultWrites[name]); err != nil {
			return err
		}
	}
	return e.record(m, item, v, ip.skipped)
}

// ErrNotHeld means 1Password does not hold a vault value after the write-back,
// so the vault copy was kept.
var ErrNotHeld = errors.New("1Password does not hold the vault's value after the write-back; the vault copy is kept")

// finishReturn reads the item back and checks that it holds every vault
// value it should, then (for a retire) moves the item to Recently Deleted,
// deletes the vault entries without a trash copy and ends the mapping.
func (e *Engine) finishReturn(ctx context.Context, ip *ItemPlan, v vault.Vault) error {
	m := ip.M
	held, err := e.OP.Get(ctx, ip.opVaultID, ip.itemID)
	if err != nil {
		return err
	}
	for f, want := range ip.expect {
		if !equalValues(f, held.Values[f], want) {
			return fmt.Errorf("%s: %w", m.NameFor(f), ErrNotHeld)
		}
	}
	if ip.kind == kindRetire {
		if err := e.OP.Delete(ctx, ip.opVaultID, ip.itemID); err != nil {
			return err
		}
	}
	if err := v.Remove(ctx, ip.remove); err != nil {
		return err
	}
	e.Mappings.Remove(m)
	delete(e.State.Mappings, m.Key())
	return e.save()
}

// ReturnUnchanged ends a mapping at once, without 1Password, when none of
// its vault entries changed since the last sync: 1Password then holds every
// value the vault has (or a newer one, with the vault's in its history), so
// the vault copy is deleted without a trash copy. It reports false, and
// changes nothing, when a sync is needed first.
func (e *Engine) ReturnUnchanged(ctx context.Context, m *mapping.Mapping) (bool, error) {
	st := e.State.Mappings[m.Key()]
	if !m.Resolved() || m.Create || st == nil || st.Item != m.Item {
		return false, nil
	}
	v := e.Vaults[m.Vault]
	names := m.EntryNames()
	entries, err := v.Entries(names)
	if err != nil {
		return false, err
	}
	var present []string
	for _, n := range names {
		prev, ok := st.Vault[n]
		if !ok || prev != entries[n].Fingerprint {
			return false, nil
		}
		if entries[n].Present {
			present = append(present, n)
		}
	}
	if err := v.Remove(ctx, present); err != nil {
		return false, err
	}
	e.Mappings.Remove(m)
	delete(e.State.Mappings, m.Key())
	return true, e.save()
}

func mismatch(err error) error {
	if errors.Is(err, onepassword.ErrVersionMismatch) {
		return ErrChanged
	}
	return err
}

// checkEntries fails when a vault entry's fingerprint moved since the plan.
func (e *Engine) checkEntries(v vault.Vault, ip *ItemPlan) error {
	now, err := v.Entries(ip.M.EntryNames())
	if err != nil {
		return err
	}
	for n, before := range ip.entries {
		if now[n].Fingerprint != before.Fingerprint {
			return ErrChanged
		}
	}
	return nil
}

// record stores the item version and the vault fingerprints after a sync.
// Skipped entries keep their previous fingerprint so their change stays pending.
func (e *Engine) record(m *mapping.Mapping, item onepassword.Item, v vault.Vault, skipped map[string]bool) error {
	entries, err := v.Entries(m.EntryNames())
	if err != nil {
		return err
	}
	prev := e.State.Mappings[m.Key()]
	st := &mapping.MappingState{Item: item.ID, OpVersion: item.Version, Vault: map[string]string{}}
	for n, en := range entries {
		if skipped[n] {
			if prev != nil && prev.Item == item.ID {
				if fp, ok := prev.Vault[n]; ok {
					st.Vault[n] = fp
				}
			}
			continue
		}
		st.Vault[n] = en.Fingerprint
	}
	e.State.Mappings[m.Key()] = st
	return e.save()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range maps.Keys(m) {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
