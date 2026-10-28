// Package cli implements the tandemvault command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/frederikb96/tandemvault/internal/config"
	"github.com/frederikb96/tandemvault/internal/onepassword"
	"github.com/frederikb96/tandemvault/internal/redact"
	"github.com/frederikb96/tandemvault/internal/vault"
)

// Exit codes.
const (
	exitOK      = 0
	exitPending = 1 // something is pending, was aborted, or an item failed
	exitError   = 2 // usage, configuration or environment error
)

const usage = `tandemvault keeps selected 1Password items in step with SOPS/age vaults.

Usage:
  tandemvault [--config FILE] <command> [flags] [args]

Sync:
  sync [--dry-run]                     show the plan, ask, apply it
  status [--local] [--quiet]           what the next sync would do; --local needs neither
                                       1Password nor a key and sees vault-side changes only
  link [flags] <title|item-id>         map a 1Password item to vault entries
  link --create [flags] <title>        create a 1Password item from vault entries
  unlink --keep op|vault|both <PREFIX> end a mapping; the other side's copy goes to its trash
  vaults                               list the 1Password vaults with their IDs

Vaults:
  vault init   [--vault V] [--age-recipient R]...
  vault names  [--vault V]
  vault get    [--vault V] [--reveal] NAME
  vault set    [--vault V] NAME        value on stdin, never as an argument
  vault unset  [--vault V] NAME        moves the entry to the vault's trash
  vault run    [--vault V] NAME... -- COMMAND [ARGS...]

  version

Configuration: --config, else $TANDEMVAULT_CONFIG, else $XDG_CONFIG_HOME/tandemvault/config.yaml.
Run "tandemvault <command> --help" for a command's flags.
`

// App is one invocation. Tests replace its streams and the 1Password backend.
type App struct {
	Version string
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	// RawStdout receives the only output that may carry a value: vault get.
	RawStdout io.Writer

	StdinIsTerminal  func() bool
	StdoutIsTerminal func() bool
	// ReadSecret prompts for a hidden value on the terminal.
	ReadSecret func(prompt string) (string, error)
	// NewBackend connects to 1Password.
	NewBackend func(ctx context.Context, c *config.Config) (onepassword.Backend, error)
	// Exec replaces the process for vault run.
	Exec func(argv0 string, argv []string, env []string) error

	configPath string
	cfg        *config.Config
	backend    onepassword.Backend
}

// New returns an App wired to the real process.
func New(version string) *App {
	return &App{
		Version:          version,
		Stdin:            os.Stdin,
		Stdout:           redact.Writer(os.Stdout),
		Stderr:           redact.Writer(os.Stderr),
		RawStdout:        os.Stdout,
		StdinIsTerminal:  func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		StdoutIsTerminal: func() bool { return term.IsTerminal(int(os.Stdout.Fd())) },
		ReadSecret:       readSecretTTY,
		NewBackend: func(ctx context.Context, c *config.Config) (onepassword.Backend, error) {
			return newBackend(ctx, c, version)
		},
		Exec: execCommand,
	}
}

func newBackend(ctx context.Context, c *config.Config, version string) (onepassword.Backend, error) {
	if err := c.NeedsOnePassword(); err != nil {
		return nil, err
	}
	switch c.OnePassword.Backend {
	case config.BackendCLI:
		return onepassword.NewCLI(c.OnePassword.Account)
	default:
		return onepassword.NewSDK(ctx, c.OnePassword.Account, version)
	}
}

func readSecretTTY(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("no terminal to ask on")
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func execCommand(argv0 string, argv []string, env []string) error {
	path, err := exec.LookPath(argv0)
	if err != nil {
		return err
	}
	return syscall.Exec(path, argv, env)
}

// Run executes args and returns the exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	global := flag.NewFlagSet("tandemvault", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	global.StringVar(&a.configPath, "config", "", "configuration file")
	help := global.Bool("help", false, "")
	global.BoolVar(help, "h", false, "")
	if err := global.Parse(args); err != nil {
		return a.fail(exitError, err)
	}
	rest := global.Args()
	if *help || len(rest) == 0 {
		fmt.Fprint(a.Stdout, usage)
		if *help {
			return exitOK
		}
		return exitError
	}
	cmd, rest := rest[0], rest[1:]
	var code int
	var err error
	switch cmd {
	case "sync":
		code, err = a.cmdSync(ctx, rest)
	case "status":
		code, err = a.cmdStatus(ctx, rest)
	case "link":
		code, err = a.cmdLink(rest)
	case "unlink":
		code, err = a.cmdUnlink(rest)
	case "vault":
		code, err = a.cmdVault(ctx, rest)
	case "vaults":
		code, err = a.cmdVaults(ctx, rest)
	case "version":
		fmt.Fprintln(a.Stdout, "tandemvault", a.Version)
		return exitOK
	case "help":
		fmt.Fprint(a.Stdout, usage)
		return exitOK
	default:
		return a.fail(exitError, fmt.Errorf("unknown command %q", cmd))
	}
	if err != nil {
		if code == exitOK {
			code = exitError
		}
		return a.fail(code, err)
	}
	return code
}

func (a *App) fail(code int, err error) int {
	if !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(a.Stderr, "tandemvault:", err)
	}
	return code
}

func (a *App) config() (*config.Config, error) {
	if a.cfg != nil {
		return a.cfg, nil
	}
	path := a.configPath
	if path == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	a.cfg = c
	return c, nil
}

// onePassword connects once per process, so the user approves once.
func (a *App) onePassword(ctx context.Context) (onepassword.Backend, error) {
	if a.backend != nil {
		return a.backend, nil
	}
	c, err := a.config()
	if err != nil {
		return nil, err
	}
	b, err := a.NewBackend(ctx, c)
	if err != nil {
		return nil, err
	}
	a.backend = b
	return b, nil
}

// passphraseFor returns the passphrase source of an age-dir vault:
//   - op://vault/item/field  read through the same 1Password connection
//   - command:<shell command> the command's standard output
//   - prompt                  asked on the terminal
func (a *App) passphraseFor(name string, confirm bool) vault.PassphraseFunc {
	return func(ctx context.Context) (string, error) {
		c, err := a.config()
		if err != nil {
			return "", err
		}
		src := c.Vaults[name].Passphrase
		switch {
		case strings.HasPrefix(src, "op://"):
			b, err := a.onePassword(ctx)
			if err != nil {
				return "", err
			}
			return b.Resolve(ctx, src)
		case strings.HasPrefix(src, "command:"):
			cmd := exec.CommandContext(ctx, "sh", "-c", strings.TrimPrefix(src, "command:"))
			cmd.Stdin = os.Stdin
			cmd.Stderr = a.Stderr
			out, err := cmd.Output()
			if err != nil {
				return "", fmt.Errorf("passphrase command failed: %w", err)
			}
			v := strings.TrimSuffix(string(out), "\n")
			redact.Register(v)
			return v, nil
		case src == "prompt":
			p, err := a.ReadSecret(fmt.Sprintf("Passphrase for vault %s: ", name))
			if err != nil {
				return "", err
			}
			if confirm {
				again, err := a.ReadSecret("Repeat passphrase: ")
				if err != nil {
					return "", err
				}
				if again != p {
					return "", errors.New("passphrases differ")
				}
			}
			redact.Register(p)
			return p, nil
		}
		return "", fmt.Errorf("vault %s: passphrase must be op://..., command:... or prompt", name)
	}
}

func (a *App) openVault(name string, confirmPassphrase bool) (vault.Vault, error) {
	c, err := a.config()
	if err != nil {
		return nil, err
	}
	return vault.Open(c, name, a.passphraseFor(name, confirmPassphrase))
}

// parseInterspersed parses flags that may appear before, between or after
// positional arguments. Everything after "--" stays positional.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			pos = append(pos, args[i:]...)
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			pos = append(pos, arg)
			continue
		}
		flags = append(flags, arg)
		name := strings.TrimLeft(arg, "-")
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return pos, nil
}

func newFlagSet(a *App, name, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(a.Stderr, "Usage: tandemvault %s\n", synopsis)
		fs.PrintDefaults()
	}
	return fs
}
