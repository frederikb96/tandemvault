package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/frederikb96/tandemvault/internal/engine"
	"github.com/frederikb96/tandemvault/internal/mapping"
	"github.com/frederikb96/tandemvault/internal/vault"
)

// localEngine loads everything that needs neither 1Password nor a key.
func (a *App) localEngine() (*engine.Engine, error) {
	c, err := a.config()
	if err != nil {
		return nil, err
	}
	mf, err := mapping.Load(c.Mappings)
	if err != nil {
		return nil, err
	}
	st, err := mapping.LoadState(c.State)
	if err != nil {
		return nil, err
	}
	vaults := map[string]vault.Vault{}
	for _, name := range c.VaultNames() {
		v, err := a.openVault(name, false)
		if err != nil {
			return nil, err
		}
		vaults[name] = v
	}
	return &engine.Engine{Config: c, Mappings: mf, State: st, Vaults: vaults}, nil
}

// runLock keeps two syncs on one machine from interleaving.
func runLock(statePath string) (release func(), err error) {
	sum := sha256.Sum256([]byte(statePath))
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	path := filepath.Join(dir, "tandemvault-"+hex.EncodeToString(sum[:])[:16]+".lock")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another tandemvault sync is running")
	}
	return func() { f.Close() }, nil
}

// plan connects to 1Password and plans the run.
func (a *App) plan(ctx context.Context) (*engine.Engine, *engine.Plan, error) {
	e, err := a.localEngine()
	if err != nil {
		return nil, nil, err
	}
	if err := e.Mappings.Validate(e.Config); err != nil {
		return nil, nil, err
	}
	blockers, err := e.Blockers()
	if err != nil {
		return nil, nil, err
	}
	if len(blockers) > 0 {
		return nil, nil, fmt.Errorf("refusing to sync while conflict copies exist, merge or remove them first:\n  %s", strings.Join(blockers, "\n  "))
	}
	if len(e.Mappings.Mappings) == 0 {
		return e, &engine.Plan{}, nil
	}
	if e.OP, err = a.onePassword(ctx); err != nil {
		return nil, nil, err
	}
	fmt.Fprintf(a.Stderr, "1Password: connected (%s)\n", e.OP.Kind())
	p, err := e.Plan(ctx)
	if err != nil {
		return nil, nil, err
	}
	return e, p, nil
}

func (a *App) cmdSync(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet(a, "sync", "sync [--dry-run]")
	dryRun := fs.Bool("dry-run", false, "show the plan and exit")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError, err
	}
	if len(pos) > 0 {
		return exitError, errors.New("sync takes no arguments")
	}
	c, err := a.config()
	if err != nil {
		return exitError, err
	}
	release, err := runLock(c.State)
	if err != nil {
		return exitError, err
	}
	defer release()

	e, p, err := a.plan(ctx)
	if err != nil {
		return exitError, err
	}
	p.Print(a.Stdout)
	planErrs := p.Errors()
	if *dryRun {
		if p.Changes() > 0 || len(planErrs) > 0 {
			return exitPending, nil
		}
		return exitOK, nil
	}
	if p.Changes() > 0 {
		fmt.Fprint(a.Stdout, "Apply? [y/N] ")
		answer, _ := bufio.NewReader(a.Stdin).ReadString('\n')
		if ans := strings.ToLower(strings.TrimSpace(answer)); ans != "y" && ans != "yes" {
			fmt.Fprintln(a.Stdout, "Aborted, nothing written.")
			return exitPending, nil
		}
	}
	applyErrs := e.Apply(ctx, p)
	for _, err := range applyErrs {
		fmt.Fprintln(a.Stderr, "failed:", err)
	}
	if p.Changes() > 0 {
		fmt.Fprintf(a.Stdout, "Applied %d of %d item(s).\n", countApplied(p)-len(applyErrs), countApplied(p))
	}
	if len(applyErrs) > 0 || len(planErrs) > 0 {
		return exitPending, nil
	}
	return exitOK, nil
}

func countApplied(p *engine.Plan) int {
	n := 0
	for _, it := range p.Items {
		if it.Err == nil && it.Changes() > 0 {
			n++
		}
	}
	return n
}

func (a *App) cmdStatus(ctx context.Context, args []string) (int, error) {
	fs := newFlagSet(a, "status", "status [--local] [--quiet]")
	local := fs.Bool("local", false, "use neither 1Password nor a key; vault-side changes only")
	quiet := fs.Bool("quiet", false, "print nothing, only set the exit code")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError, err
	}
	if len(pos) > 0 {
		return exitError, errors.New("status takes no arguments")
	}
	if !*local {
		_, p, err := a.plan(ctx)
		if err != nil {
			return exitError, err
		}
		if !*quiet {
			p.Print(a.Stdout)
		}
		if p.Changes() > 0 || len(p.Errors()) > 0 {
			return exitPending, nil
		}
		return exitOK, nil
	}
	e, err := a.localEngine()
	if err != nil {
		return exitError, err
	}
	pending, err := e.LocalStatus()
	if err != nil {
		return exitError, err
	}
	if !*quiet {
		if len(pending) == 0 {
			fmt.Fprintln(a.Stdout, "Nothing pending on the vault side. Changes made in 1Password show only in a full status or sync.")
		} else {
			fmt.Fprintln(a.Stdout, "Pending for the next sync (vault side only; 1Password changes show in a full status):")
			for _, l := range pending {
				fmt.Fprintln(a.Stdout, "  "+l)
			}
		}
	}
	if len(pending) > 0 {
		return exitPending, nil
	}
	return exitOK, nil
}
