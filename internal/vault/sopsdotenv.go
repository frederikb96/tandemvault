package vault

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/frederikb96/tandemvault/internal/config"
	"github.com/frederikb96/tandemvault/internal/redact"
)

// SopsDotenv is a sops-encrypted dotenv file. Every operation runs the sops
// binary; values travel over pipes, never on the command line.
type SopsDotenv struct {
	name       string
	path       string
	ageKeyFile string

	cache map[string]string
}

var (
	dotenvLineRE    = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
	ageRecipientRE  = regexp.MustCompile(`^sops_age__list_[0-9]+__map_recipient=(.+)$`)
	dotenvSopsFlags = []string{"--input-type", "dotenv", "--output-type", "dotenv"}
)

func (s *SopsDotenv) Name() string { return s.name }
func (s *SopsDotenv) Type() string { return config.TypeSopsDotenv }

// Path is the vault file.
func (s *SopsDotenv) Path() string { return s.path }

// TrashPath is the sops file entries are moved to: ".sops.env" → ".sops.trash.env".
func (s *SopsDotenv) TrashPath() string {
	ext := filepath.Ext(s.path)
	return strings.TrimSuffix(s.path, ext) + ".trash" + ext
}

// rawLines maps each name to its encrypted value as written in the file.
func rawLines(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		m := dotenvLineRE.FindStringSubmatch(sc.Text())
		if m == nil || strings.HasPrefix(m[1], "sops_") {
			continue
		}
		out[m[1]] = m[2]
	}
	return out, sc.Err()
}

func (s *SopsDotenv) Names() ([]string, error) {
	raw, err := rawLines(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(raw))
	for n := range raw {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

func (s *SopsDotenv) Entries(names []string) (map[string]Entry, error) {
	out := make(map[string]Entry, len(names))
	st, err := os.Stat(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			for _, n := range names {
				out[n] = Entry{}
			}
			return out, nil
		}
		return nil, err
	}
	raw, err := rawLines(s.path)
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		v, ok := raw[n]
		if !ok {
			out[n] = Entry{}
			continue
		}
		out[n] = Entry{Present: true, Fingerprint: fingerprint([]byte(v)), ModTime: st.ModTime().UTC()}
	}
	return out, nil
}

func (s *SopsDotenv) Read(ctx context.Context, names []string) (map[string]string, error) {
	if s.cache == nil {
		if _, err := os.Stat(s.path); err != nil {
			return nil, err
		}
		stdout, err := s.sops(ctx, nil, "-d", "--input-type", "dotenv", "--output-type", "json", s.path)
		if err != nil {
			return nil, fmt.Errorf("sops could not decrypt %s: %w", s.path, err)
		}
		var all map[string]string
		if err := json.Unmarshal(stdout, &all); err != nil {
			return nil, fmt.Errorf("sops returned unexpected output for %s", s.path)
		}
		s.cache = map[string]string{}
		for k, v := range all {
			if strings.HasPrefix(k, "sops_") {
				continue
			}
			s.cache[k] = unquote(v)
		}
	}
	out := map[string]string{}
	for _, n := range names {
		if v, ok := s.cache[n]; ok {
			redact.Register(v)
			out[n] = v
		}
	}
	return out, nil
}

func (s *SopsDotenv) Write(ctx context.Context, name, value string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	redact.Register(value)
	err := WithLock(LockPath(s.path), func() error { return s.set(ctx, s.path, name, value) })
	if err == nil && s.cache != nil {
		s.cache[name] = value
	}
	return err
}

// set runs `sops set` with the value as a JSON string on stdin.
func (s *SopsDotenv) set(ctx context.Context, path, name, value string) error {
	payload, err := json.Marshal(quoteSafe(value))
	if err != nil {
		return err
	}
	args := append([]string{"set", "--value-stdin"}, dotenvSopsFlags...)
	args = append(args, path, fmt.Sprintf(`["%s"]`, name))
	if _, err := s.sops(ctx, payload, args...); err != nil {
		return fmt.Errorf("sops set %s in %s: %w", name, path, err)
	}
	return nil
}

func (s *SopsDotenv) unset(ctx context.Context, name string) error {
	args := append([]string{"unset"}, dotenvSopsFlags...)
	args = append(args, s.path, fmt.Sprintf(`["%s"]`, name))
	if _, err := s.sops(ctx, nil, args...); err != nil {
		return fmt.Errorf("sops unset %s in %s: %w", name, s.path, err)
	}
	return nil
}

// Trash moves entries into the trash file as <NAME>__<stamp>. The trash entry
// is written before the original is removed, so an interruption leaves a
// value in both files rather than in neither.
func (s *SopsDotenv) Trash(ctx context.Context, names []string, stamp string) error {
	for _, n := range names {
		if err := ValidName(n); err != nil {
			return err
		}
	}
	values, err := s.Read(ctx, names)
	if err != nil {
		return err
	}
	return WithLock(LockPath(s.path), func() error {
		trash := s.TrashPath()
		if _, err := os.Stat(trash); errors.Is(err, os.ErrNotExist) {
			recipients, err := s.recipients()
			if err != nil {
				return err
			}
			if err := s.encryptEmpty(ctx, trash, recipients); err != nil {
				return err
			}
		}
		existing, err := rawLines(trash)
		if err != nil {
			return err
		}
		for _, n := range names {
			v, ok := values[n]
			if !ok {
				continue
			}
			key := n + "__" + stamp
			for i := 2; existing[key] != ""; i++ {
				key = fmt.Sprintf("%s__%s_%d", n, stamp, i)
			}
			existing[key] = "x"
			if err := s.set(ctx, trash, key, v); err != nil {
				return err
			}
			if err := s.unset(ctx, n); err != nil {
				return err
			}
			delete(s.cache, n)
		}
		return nil
	})
}

func (s *SopsDotenv) Remove(ctx context.Context, names []string) error {
	raw, err := rawLines(s.path)
	if err != nil {
		return err
	}
	return WithLock(LockPath(s.path), func() error {
		for _, n := range names {
			if err := ValidName(n); err != nil {
				return err
			}
			if _, ok := raw[n]; !ok {
				continue
			}
			if err := s.unset(ctx, n); err != nil {
				return err
			}
			delete(s.cache, n)
		}
		return nil
	})
}

// recipients reads the age recipients from the file's sops metadata.
func (s *SopsDotenv) recipients() ([]string, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		if m := ageRecipientRE.FindStringSubmatch(sc.Text()); m != nil {
			out = append(out, strings.TrimSpace(m[1]))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s has no age recipients in its sops metadata", s.path)
	}
	return out, sc.Err()
}

func (s *SopsDotenv) encryptEmpty(ctx context.Context, path string, recipients []string) error {
	if len(recipients) == 0 {
		return errors.New("at least one age recipient is required")
	}
	args := []string{"--config", os.DevNull, "encrypt", "--age", strings.Join(recipients, ",")}
	args = append(args, dotenvSopsFlags...)
	args = append(args, "/dev/stdin")
	out, err := s.sops(ctx, []byte{}, args...)
	if err != nil {
		return fmt.Errorf("sops could not create %s: %w", path, err)
	}
	return WriteFileAtomic(path, out, 0o600)
}

func (s *SopsDotenv) Init(ctx context.Context, opts InitOptions) error {
	if _, err := os.Stat(s.path); err == nil {
		return fmt.Errorf("%s already exists", s.path)
	}
	return s.encryptEmpty(ctx, s.path, opts.AgeRecipients)
}

func (s *SopsDotenv) ConflictCopies() ([]string, error) {
	a, err := ConflictCopiesOf(s.path)
	if err != nil {
		return nil, err
	}
	b, err := ConflictCopiesOf(s.TrashPath())
	return append(a, b...), err
}

func (s *SopsDotenv) sops(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	bin, err := exec.LookPath("sops")
	if err != nil {
		return nil, errors.New("sops not found on PATH")
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = filepath.Dir(s.path)
	cmd.Env = os.Environ()
	if s.ageKeyFile != "" {
		cmd.Env = append(cmd.Env, "SOPS_AGE_KEY_FILE="+s.ageKeyFile)
	}
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
		return nil, errors.New(redact.String(msg))
	}
	return stdout.Bytes(), nil
}

// Dotenv readers strip one pair of surrounding quotes. A value that is itself
// wrapped in quotes is stored with an extra pair so it survives that.
func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

func quoteSafe(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return string(v[0]) + v + string(v[0])
	}
	return v
}
