package onepassword

import "strings"

// matchCandidates picks the items whose ID equals query, else whose title
// equals it exactly, else whose title equals it ignoring case.
func matchCandidates(all []Candidate, query string) []Candidate {
	var byID, exact, folded []Candidate
	for _, c := range all {
		switch {
		case c.ID == query:
			byID = append(byID, c)
		case c.Title == query:
			exact = append(exact, c)
		case strings.EqualFold(c.Title, query):
			folded = append(folded, c)
		}
	}
	switch {
	case len(byID) > 0:
		return byID
	case len(exact) > 0:
		return exact
	}
	return folded
}

// vaultMatches reports whether ref (a vault ID, or empty for every vault) selects vault id.
// Vaults are never matched by title: the SDK and op name the same vault
// differently (a business account's personal vault is "Employee" in op and "Individual" in the SDK).
func vaultMatches(ref, id string) bool {
	return ref == "" || ref == id
}
