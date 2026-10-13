// Package dlp scans text for secrets, PII and company keywords. It reports
// rule names and counts, never the matched text.
package dlp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// dlpRule flags a class of sensitive data by pattern. count, when set, does a
// second pass over each match and returns how many real hits it holds (e.g.
// card numbers that pass Luhn), to cut false positives; zero rejects it.
type Rule struct {
	Name  string
	Re    *regexp.Regexp
	Count func(string) int
}

// Hits returns how many times the rule fires in text.
func (r Rule) Hits(text string) int {
	n := 0
	for _, m := range r.Re.FindAllString(text, -1) {
		if r.Count == nil {
			n++
		} else {
			n += r.Count(m)
		}
	}
	return n
}

// BuiltinRules detect common secrets and PII. They match structure, not the
// secret's value, so nothing here needs a real credential to test.
var BuiltinRules = []Rule{
	{Name: "private-key", Re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{Name: "aws-access-key", Re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{Name: "gcp-api-key", Re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	// Google OAuth access tokens (ya29.) and refresh tokens (1//0), as gcloud,
	// ADC and the Google SDKs hold them.
	{Name: "google-oauth-token", Re: regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{30,}|\b1//0[0-9A-Za-z_-]{30,}`)},
	{Name: "openai-key", Re: regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`)},
	{Name: "anthropic-key", Re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`)},
	{Name: "github-token", Re: regexp.MustCompile(`\bgh[opsu]_[A-Za-z0-9]{36,}\b`)},
	{Name: "slack-token", Re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{Name: "jwt", Re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
	{Name: "email", Re: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)},
	{Name: "us-ssn", Re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	// A run of digit groups split by single spaces, dashes, or dots. The run is
	// matched whole and searched for cards in cardsIn, because a greedy 13-19
	// digit match would swallow a trailing expiry or CVV and fail Luhn.
	{Name: "credit-card", Re: regexp.MustCompile(`\b\d+(?:[ .-]\d+)*\b`), Count: cardsIn},
}

// cardsIn counts card numbers in a run of digit groups. A card is a window of
// whole consecutive groups holding 13 to 19 digits that starts with a card
// network digit (2 to 6) and passes Luhn. Windows start at every group, so a
// number stays visible when an order ID precedes it or an expiry and CVV
// follow it on the same line; a found card's groups are not reused.
func cardsIn(run string) int {
	groups := strings.FieldsFunc(run, func(r rune) bool { return r == ' ' || r == '-' || r == '.' })
	n := 0
	for i := 0; i < len(groups); {
		found := 0
		digits := 0
		for j := i; j < len(groups) && digits < 19; j++ {
			digits += len(groups[j])
			if digits >= 13 && digits <= 19 && groups[i][0] >= '2' && groups[i][0] <= '6' &&
				luhnValid(strings.Join(groups[i:j+1], "")) {
				found = j - i + 1
				break
			}
		}
		if found > 0 {
			n++
			i += found
		} else {
			i++
		}
	}
	return n
}

// luhnValid reports whether the digits in s pass the Luhn checksum, which
// every real card number does. It filters out arbitrary long digit strings.
func luhnValid(s string) bool {
	var sum, n int
	alt := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
		n++
	}
	return n >= 13 && sum%10 == 0
}

type Finding struct {
	Rule  string
	Count int
}

// Scanner holds the active rule set: built-ins plus any user keywords.
type Scanner struct {
	Rules []Rule
}

// NewScanner builds a scanner. Each keyword becomes a case-insensitive
// literal rule named "keyword:<word>", for internal markers like a project
// codename or "CONFIDENTIAL".
func NewScanner(keywords []string) *Scanner {
	rules := append([]Rule(nil), BuiltinRules...)
	for _, kw := range keywords {
		kw = strings.TrimSpace(kw)
		if kw == "" {
			continue
		}
		rules = append(rules, Rule{
			Name: "keyword:" + kw,
			Re:   regexp.MustCompile(`(?i)` + regexp.QuoteMeta(kw)),
		})
	}
	return &Scanner{Rules: rules}
}

// Scan returns one finding per rule that matched, with a count. It never
// returns the matched text, so callers can log findings without re-recording
// the sensitive value.
func (s *Scanner) Scan(text string) []Finding {
	var out []Finding
	for _, r := range s.Rules {
		if n := r.Hits(text); n > 0 {
			out = append(out, Finding{Rule: r.Name, Count: n})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}

// Summary renders findings as "rule:count,rule:count" for a log field.
func Summary(fs []Finding) string {
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = fmt.Sprintf("%s:%d", f.Rule, f.Count)
	}
	return strings.Join(parts, ",")
}

func (f Finding) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Rule  string `json:"rule"`
		Count int    `json:"count"`
	}{f.Rule, f.Count})
}
