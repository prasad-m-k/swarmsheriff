// Package policy loads and validates the JSON policy file: data classes,
// detectors, destination categories, actions and modes.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"swarmsheriff/internal/dlp"
)

// Verdict is the outcome for a request. Values are ordered by strictness, so
// the strictest of several verdicts is simply the largest.
type Verdict int

const (
	VerdictAllow Verdict = iota
	VerdictTranslate
	VerdictHold
	VerdictBlock
)

var verdictNames = []string{"allow", "translate", "hold", "block"}

func (v Verdict) String() string { return verdictNames[v] }

func parseVerdict(s string) (Verdict, bool) {
	for i, n := range verdictNames {
		if s == n {
			return Verdict(i), true
		}
	}
	return 0, false
}

const (
	ModeReport  = "report"
	ModeEnforce = "enforce"
)

// policyVersion is the only schema version this build understands.
const policyVersion = 1

// Policy is the company policy file: destination categories and the classes
// of data to protect. Classes are data, so adding one needs no code change.
type Policy struct {
	Version      int                 `json:"version"`
	Mode         string              `json:"mode"`
	Destinations map[string][]string `json:"destinations"`
	Classes      []*Class            `json:"classes"`
}

type Class struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	Owner       string            `json:"owner"`
	Detectors   Detectors         `json:"detectors"`
	Classifier  ClassifierConfig  `json:"classifier"`
	Actions     map[string]string `json:"actions"`
	Mode        string            `json:"mode"`

	// Compiled at load time.
	actions  map[string]Verdict
	Labels   map[string]bool
	Globs    []*regexp.Regexp
	Keywords *regexp.Regexp
	Rules    []dlp.Rule
	Prints   map[string]bool
}

// Detectors are the deterministic signals for a class. Rules entries are
// either a built-in rule name from dlp.go ("aws-access-key") or a regular
// expression prefixed with "re:". Fingerprints are lowercase hex SHA-256
// hashes of exact text (see fingerprintsOf).
type Detectors struct {
	SourceLabels []string `json:"source_labels"`
	PathGlobs    []string `json:"path_globs"`
	Keywords     []string `json:"keywords"`
	Rules        []string `json:"rules"`
	Fingerprints []string `json:"fingerprints"`
}

// ClassifierConfig controls the probabilistic step for a class. HoldAt of 0
// means no hold band: below BlockAt the classifier does not affect the verdict.
type ClassifierConfig struct {
	Enabled          bool     `json:"enabled"`
	BlockAt          float64  `json:"block_at"`
	HoldAt           float64  `json:"hold_at"`
	Raw              bool     `json:"classifier_raw"`
	ExamplesPositive []string `json:"examples_positive"`
	ExamplesNegative []string `json:"examples_negative"`
}

// Load reads and validates a policy file. The first problem found is
// returned with the class ID and field name, so a bad file is easy to fix.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePolicy(data)
}

func ParsePolicy(data []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields() // a misspelled field would otherwise silently disable a detector
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := p.compile(); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return &p, nil
}

var BuiltinRuleByName = func() map[string]dlp.Rule {
	m := map[string]dlp.Rule{}
	for _, r := range dlp.BuiltinRules {
		m[r.Name] = r
	}
	return m
}()

var hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (p *Policy) compile() error {
	if p.Version != policyVersion {
		return fmt.Errorf("field \"version\": got %d, want %d", p.Version, policyVersion)
	}
	if p.Mode == "" {
		p.Mode = ModeReport
	}
	if p.Mode != ModeReport && p.Mode != ModeEnforce {
		return fmt.Errorf("field \"mode\": %q is not report or enforce", p.Mode)
	}
	if len(p.Destinations) == 0 {
		return errors.New("field \"destinations\": at least one category is required")
	}
	seenHost := map[string]string{}
	for cat, hosts := range p.Destinations {
		for _, h := range hosts {
			h = strings.ToLower(h)
			if prev, ok := seenHost[h]; ok && prev != cat {
				return fmt.Errorf("field \"destinations\": host %q is in both %q and %q", h, prev, cat)
			}
			seenHost[h] = cat
		}
	}
	if len(p.Classes) == 0 {
		return errors.New("field \"classes\": at least one class is required")
	}
	ids := map[string]bool{}
	for i, c := range p.Classes {
		if c == nil {
			return fmt.Errorf("classes[%d]: null class", i)
		}
		if c.ID == "" {
			return fmt.Errorf("classes[%d]: field \"id\" is required", i)
		}
		if ids[c.ID] {
			return fmt.Errorf("class %q: field \"id\" is duplicated", c.ID)
		}
		ids[c.ID] = true
		if err := c.compile(p.Destinations); err != nil {
			return fmt.Errorf("class %q: %w", c.ID, err)
		}
	}
	return nil
}

func (c *Class) compile(dests map[string][]string) error {
	if c.Description == "" {
		return errors.New("field \"description\" is required")
	}
	if c.Owner == "" {
		return errors.New("field \"owner\" is required")
	}
	if c.Mode != "" && c.Mode != ModeReport && c.Mode != ModeEnforce {
		return fmt.Errorf("field \"mode\": %q is not report or enforce", c.Mode)
	}

	c.actions = map[string]Verdict{}
	for cat := range dests {
		s, ok := c.Actions[cat]
		if !ok {
			return fmt.Errorf("field \"actions\": missing destination category %q", cat)
		}
		v, ok := parseVerdict(s)
		if !ok {
			return fmt.Errorf("field \"actions\": %q for %q is not allow, translate, hold, or block", s, cat)
		}
		c.actions[cat] = v
	}
	for cat := range c.Actions {
		if _, ok := dests[cat]; !ok {
			return fmt.Errorf("field \"actions\": unknown destination category %q", cat)
		}
	}

	d := c.Detectors
	c.Labels = map[string]bool{}
	for _, l := range d.SourceLabels {
		c.Labels[l] = true
	}
	for _, g := range d.PathGlobs {
		re, err := globRegexp(g)
		if err != nil {
			return fmt.Errorf("field \"path_globs\": %q: %w", g, err)
		}
		c.Globs = append(c.Globs, re)
	}
	var kws []string
	for _, kw := range d.Keywords {
		if kw = strings.TrimSpace(kw); kw != "" {
			kws = append(kws, regexp.QuoteMeta(kw))
		}
	}
	if len(kws) > 0 {
		c.Keywords = regexp.MustCompile(`(?i)` + strings.Join(kws, "|"))
	}
	for _, r := range d.Rules {
		if expr, ok := strings.CutPrefix(r, "re:"); ok {
			re, err := regexp.Compile(expr)
			if err != nil {
				return fmt.Errorf("field \"rules\": %q: %w", r, err)
			}
			c.Rules = append(c.Rules, dlp.Rule{Name: r, Re: re})
			continue
		}
		br, ok := BuiltinRuleByName[r]
		if !ok {
			return fmt.Errorf("field \"rules\": %q is not a built-in rule name or a re: pattern", r)
		}
		c.Rules = append(c.Rules, br)
	}
	c.Prints = map[string]bool{}
	for _, f := range d.Fingerprints {
		if !hexSHA256.MatchString(f) {
			return fmt.Errorf("field \"fingerprints\": %q is not a lowercase hex SHA-256", f)
		}
		c.Prints[f] = true
	}

	cl := c.Classifier
	if cl.Enabled {
		if cl.BlockAt <= 0 || cl.BlockAt > 1 {
			return fmt.Errorf("field \"classifier.block_at\": %v is not in (0, 1]", cl.BlockAt)
		}
		if cl.HoldAt < 0 || cl.HoldAt > cl.BlockAt {
			return fmt.Errorf("field \"classifier.hold_at\": %v is not in [0, block_at]", cl.HoldAt)
		}
	}
	return nil
}

// Category returns the destination category for host. A host matches a listed
// entry when it equals it or is a subdomain of it.
func (p *Policy) Category(host string) (string, bool) {
	host = strings.ToLower(host)
	if h, _, ok := strings.Cut(host, ":"); ok {
		host = h
	}
	for cat, hosts := range p.Destinations {
		for _, h := range hosts {
			h = strings.ToLower(h)
			if host == h || strings.HasSuffix(host, "."+h) {
				return cat, true
			}
		}
	}
	return "", false
}

// Action returns the class's verdict for a destination category. An unlisted
// destination gets the class's strictest action.
func (c *Class) Action(category string) Verdict {
	if v, ok := c.actions[category]; ok {
		return v
	}
	var strictest Verdict
	for _, v := range c.actions {
		strictest = max(strictest, v)
	}
	return strictest
}

func (p *Policy) ModeFor(c *Class) string {
	if c.Mode != "" {
		return c.Mode
	}
	return p.Mode
}

// RawClassifierClasses lists classes that send raw content to the classifier,
// for the startup log.
func (p *Policy) RawClassifierClasses() []string {
	var ids []string
	for _, c := range p.Classes {
		if c.Classifier.Enabled && c.Classifier.Raw {
			ids = append(ids, c.ID)
		}
	}
	return ids
}

// globRegexp converts a path glob to an anchored regexp. "**" crosses
// directory separators, "*" and "?" do not.
func globRegexp(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); i++ {
		switch c := glob[i]; c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				i++
				if i+1 < len(glob) && glob[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

func SplitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
