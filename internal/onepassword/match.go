package onepassword

import "strings"

// How a candidate matched the lookup.
const (
	MatchID      = "id"
	MatchExact   = "exact title"
	MatchFolded  = "title ignoring case"
	MatchPartial = "title contains the search"
)

// MatchCandidates picks the items whose ID equals query, else whose title
// equals it exactly, else ignoring case, else whose title contains it
// ignoring case. Each returned candidate carries how it matched.
func MatchCandidates(all []Candidate, query string) []Candidate {
	tiers := map[string][]Candidate{}
	q := strings.ToLower(query)
	for _, c := range all {
		var kind string
		switch {
		case c.ID == query:
			kind = MatchID
		case c.Title == query:
			kind = MatchExact
		case strings.EqualFold(c.Title, query):
			kind = MatchFolded
		case q != "" && strings.Contains(strings.ToLower(c.Title), q):
			kind = MatchPartial
		default:
			continue
		}
		c.Match = kind
		tiers[kind] = append(tiers[kind], c)
	}
	for _, kind := range []string{MatchID, MatchExact, MatchFolded, MatchPartial} {
		if len(tiers[kind]) > 0 {
			return tiers[kind]
		}
	}
	return nil
}

// vaultMatches reports whether ref (a vault ID, or empty for every vault) selects vault id.
// Vaults are never matched by title: the SDK and op name the same vault
// differently (a business account's personal vault is "Employee" in op and "Individual" in the SDK).
func vaultMatches(ref, id string) bool {
	return ref == "" || ref == id
}
