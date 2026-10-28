// Package config loads tandemvault's configuration file.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Vault types.
const (
	TypeSopsDotenv = "sops-dotenv"
	TypeAgeDir     = "age-dir"
)

// 1Password backends.
const (
	BackendSDK = "sdk"
	BackendCLI = "cli"
)

// Config is the parsed configuration file. Relative paths are resolved
// against the directory holding the file.
type Config struct {
	OnePassword OnePassword      `yaml:"onepassword"`
	Vaults      map[string]Vault `yaml:"vaults"`
	Mappings    string           `yaml:"mappings"`
	State       string           `yaml:"state"`

	// Path is the file the configuration was read from.
	Path string `yaml:"-"`
}

// OnePassword configures how the 1Password side is reached.
type OnePassword struct {
	// Account is the account name shown in the desktop app's sidebar, or the account UUID.
	Account string `yaml:"account"`
	// Backend is "sdk" (desktop app integration, the default) or "cli" (the op command).
	Backend string `yaml:"backend"`
}

// Vault is one configured vault.
type Vault struct {
	Type string `yaml:"type"`

	// sops-dotenv
	Path       string `yaml:"path"`
	AgeKeyFile string `yaml:"age_key_file"`

	// age-dir
	Dir        string `yaml:"dir"`
	Identity   string `yaml:"identity"`
	Recipient  string `yaml:"recipient"`
	Passphrase string `yaml:"passphrase"`
}

var vaultNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// DefaultPath is $TANDEMVAULT_CONFIG, else $XDG_CONFIG_HOME/tandemvault/config.yaml.
func DefaultPath() (string, error) {
	if p := os.Getenv("TANDEMVAULT_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tandemvault", "config.yaml"), nil
}

// Load reads and validates the configuration at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no configuration at %s (see the README for a starting point)", path)
		}
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c.Path = abs
	if err := c.resolve(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) resolve() error {
	base := filepath.Dir(c.Path)
	if c.OnePassword.Backend == "" {
		c.OnePassword.Backend = BackendSDK
	}
	switch c.OnePassword.Backend {
	case BackendSDK, BackendCLI:
	default:
		return fmt.Errorf("onepassword.backend must be %q or %q", BackendSDK, BackendCLI)
	}
	if len(c.Vaults) == 0 {
		return errors.New("no vaults configured")
	}
	for name, v := range c.Vaults {
		if !vaultNameRE.MatchString(name) {
			return fmt.Errorf("vault name %q: use lowercase letters, digits and dashes", name)
		}
		switch v.Type {
		case TypeSopsDotenv:
			if v.Path == "" {
				return fmt.Errorf("vault %s: path is required", name)
			}
			if v.Dir != "" || v.Identity != "" || v.Recipient != "" || v.Passphrase != "" {
				return fmt.Errorf("vault %s: dir, identity, recipient and passphrase belong to age-dir vaults", name)
			}
			v.Path = expand(base, v.Path)
			if v.AgeKeyFile != "" {
				v.AgeKeyFile = expand(base, v.AgeKeyFile)
			}
		case TypeAgeDir:
			if v.Dir == "" || v.Passphrase == "" {
				return fmt.Errorf("vault %s: dir and passphrase are required", name)
			}
			if v.Path != "" || v.AgeKeyFile != "" {
				return fmt.Errorf("vault %s: path and age_key_file belong to sops-dotenv vaults", name)
			}
			v.Dir = expand(base, v.Dir)
			if v.Identity == "" {
				v.Identity = v.Dir + "-identity.age"
			}
			if v.Recipient == "" {
				v.Recipient = v.Dir + ".recipient"
			}
			v.Identity = expand(base, v.Identity)
			v.Recipient = expand(base, v.Recipient)
		default:
			return fmt.Errorf("vault %s: type must be %q or %q", name, TypeSopsDotenv, TypeAgeDir)
		}
		c.Vaults[name] = v
	}
	if c.Mappings == "" {
		c.Mappings = "mappings.yaml"
	}
	if c.State == "" {
		c.State = "state.json"
	}
	c.Mappings = expand(base, c.Mappings)
	c.State = expand(base, c.State)
	return nil
}

// NeedsOnePassword reports whether the account is set; commands that reach
// 1Password call it first.
func (c *Config) NeedsOnePassword() error {
	if c.OnePassword.Account == "" {
		return fmt.Errorf("%s: onepassword.account is required for this command", c.Path)
	}
	return nil
}

// VaultNames returns the configured vault names, sorted.
func (c *Config) VaultNames() []string {
	names := make([]string, 0, len(c.Vaults))
	for n := range c.Vaults {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// PickVault returns name if set, else the only configured vault.
func (c *Config) PickVault(name string) (string, error) {
	if name == "" {
		if len(c.Vaults) == 1 {
			return c.VaultNames()[0], nil
		}
		return "", fmt.Errorf("several vaults are configured, name one with --vault (%s)", strings.Join(c.VaultNames(), ", "))
	}
	if _, ok := c.Vaults[name]; !ok {
		return "", fmt.Errorf("no vault named %q (configured: %s)", name, strings.Join(c.VaultNames(), ", "))
	}
	return name, nil
}

func expand(base, p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	return filepath.Clean(p)
}
