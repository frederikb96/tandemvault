// Package redact keeps secret values out of anything the tool prints.
//
// Plans, logs and errors are built from names only. As a second line of
// defence every value the process loads is registered here, and the writers
// wrapping stdout and stderr replace any registered value before it is
// written.
package redact

import (
	"io"
	"sort"
	"strings"
	"sync"
)

// MinLength is the shortest value that is registered. Shorter values would
// blank out ordinary words in the output.
const MinLength = 4

const mask = "[redacted]"

var (
	mu     sync.RWMutex
	values = map[string]struct{}{}
)

// Register adds values to the redaction list.
func Register(vs ...string) {
	mu.Lock()
	defer mu.Unlock()
	for _, v := range vs {
		v = strings.TrimSpace(v)
		if len(v) >= MinLength {
			values[v] = struct{}{}
		}
	}
}

// String returns s with every registered value replaced.
func String(s string) string {
	mu.RLock()
	defer mu.RUnlock()
	if len(values) == 0 {
		return s
	}
	// Longest first, so a value containing another is masked whole.
	sorted := make([]string, 0, len(values))
	for v := range values {
		sorted = append(sorted, v)
	}
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, v := range sorted {
		s = strings.ReplaceAll(s, v, mask)
	}
	return s
}

// Writer wraps w so that everything written through it is redacted.
func Writer(w io.Writer) io.Writer { return &writer{w: w} }

type writer struct{ w io.Writer }

func (r *writer) Write(p []byte) (int, error) {
	if _, err := io.WriteString(r.w, String(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Reset empties the list. Tests use it between cases.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	values = map[string]struct{}{}
}
