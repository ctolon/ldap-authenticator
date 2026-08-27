package ldapauth

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

// Templates in this package use a single placeholder syntax, {{name}}. The
// placeholder is replaced by a value that has already been escaped for the
// grammar it is being spliced into — RFC 4515 for search filters, RFC 4514
// for distinguished names. There is no way to interpolate an unescaped
// value, which is the point: LDAP injection is not a class of bug this
// package leaves available to its callers.
//
// The recognised placeholders are:
//
//	{{username}}    the username as supplied by the caller
//	{{base_dn}}     the configured base DN for the search
//	{{user_dn}}     the authenticated user's DN (group templates only)
//
// All three are escaped, for whichever grammar they are being spliced
// into. It is tempting to exempt the two that are distinguished names, on
// the grounds that a DN is structure rather than a value — and that is a
// mistake. A DN written into a search filter is an assertion value like
// any other, and under a direct bind {{user_dn}} is built from the
// username, so exempting it would put caller input into a filter unescaped.
const (
	placeholderUsername = "username"
	placeholderBaseDN   = "base_dn"
	placeholderUserDN   = "user_dn"
)

// escapeFilterValue and escapeDNValue are go-ldap's own escapers, named
// here so that every call site reads as "escape this for the grammar it is
// going into" rather than as a library call, and so that the package's
// fuzz targets have a single symbol to aim at.
//
// They are not reimplemented. go-ldap already escapes the RFC 4515 set
// `()*\` plus everything outside 0 < c < 0x80, and the RFC 4514 set
// `"+,;<>\` plus a leading `#`, a leading or trailing space, and NUL. A
// second implementation here would be a second thing to keep correct, and
// the fuzz targets assert the property either way — that what comes out
// contributes no structure to what it is spliced into.
var (
	escapeFilterValue = ldap.EscapeFilter

	escapeDNValue = ldap.EscapeDN
)

// template is a parsed placeholder template. Parsing happens once, at
// construction, so that a malformed template is a startup failure and the
// hot path is a slice walk rather than a scan.
type template struct {
	// raw is kept for error messages and for String.
	raw string

	// literals and holes interleave: literals[0] + holes[0] +
	// literals[1] + ... There is always exactly one more literal than
	// hole.
	literals []string
	holes    []string
}

// parseTemplate parses a {{name}} template, accepting only the
// placeholders in allowed. A template containing a single %s and no
// {{...}} is accepted as shorthand for {{username}}: that is the spelling
// used by most existing LDAP configuration in the wild, and refusing it
// would make migrating to this package a search-and-replace exercise for
// no gain.
func parseTemplate(raw string, allowed ...string) (template, error) {
	t := template{raw: raw}

	if raw == "" {
		return t, fmt.Errorf("%w: template is empty", ErrInvalidOption)
	}

	if !utf8.ValidString(raw) {
		return t, fmt.Errorf("%w: template %q is not valid UTF-8", ErrInvalidOption, raw)
	}

	if !strings.Contains(raw, "{{") && strings.Count(raw, "%s") == 1 {
		raw = strings.Replace(raw, "%s", "{{"+placeholderUsername+"}}", 1)
	}

	rest := raw

	for {
		open := strings.Index(rest, "{{")
		if open < 0 {
			t.literals = append(t.literals, rest)

			break
		}

		close := strings.Index(rest[open:], "}}")
		if close < 0 {
			return t, fmt.Errorf("%w: template %q has an unclosed {{", ErrInvalidOption, t.raw)
		}

		name := strings.TrimSpace(rest[open+2 : open+close])
		if !slices.Contains(allowed, name) {
			return t, fmt.Errorf(
				"%w: template %q uses unknown placeholder {{%s}}, expected one of %s",
				ErrInvalidOption, t.raw, name, strings.Join(allowed, ", "),
			)
		}

		t.literals = append(t.literals, rest[:open])
		t.holes = append(t.holes, name)
		rest = rest[open+close+2:]
	}

	if len(t.holes) == 0 {
		return t, fmt.Errorf(
			"%w: template %q has no placeholder; expected at least one of %s",
			ErrInvalidOption, t.raw, strings.Join(allowed, ", "),
		)
	}

	return t, nil
}

// requires reports whether the template uses the named placeholder.
func (t template) requires(name string) bool { return slices.Contains(t.holes, name) }

// expand renders the template, passing every substituted value through
// escape first. A template that was never parsed renders as the empty
// string, which is what an unset optional template should do.
func (t template) expand(escape func(string) string, vars map[string]string) string {
	if len(t.literals) == 0 {
		return ""
	}

	var b strings.Builder

	b.Grow(len(t.raw) + 32)

	for i, lit := range t.literals {
		b.WriteString(lit)

		if i < len(t.holes) {
			b.WriteString(escape(vars[t.holes[i]]))
		}
	}

	return b.String()
}

// isZero reports whether the template was never set.
func (t template) isZero() bool { return t.raw == "" }

func (t template) String() string { return t.raw }

// verbatim substitutes a value unchanged.
//
// Nothing in the package uses it any more, and that is the point: the one
// place that did — splicing a DN into a search filter — is what shipped an
// authorisation bypass. It is kept because the template tests need a way
// to check expansion separately from escaping, and it is unexported so
// that no caller can reach for it.
func verbatim(s string) string { return s }

// expandFilter renders a search-filter template, escaping every value it
// splices in for RFC 4515.
//
// Every value, including the ones that are distinguished names. A DN used
// as an assertion value is an assertion value, and RFC 4515 says an
// assertion value is escaped — the fact that it is also a DN changes
// nothing about the grammar it is being written into.
//
// This is safe as well as correct, which is worth being explicit about
// because the temptation is to think otherwise: ldap.EscapeFilter escapes
// only `(`, `)`, `*`, `\`, NUL, and bytes above 0x7f. A DN's commas,
// equals signs, and spaces pass through untouched, so an escaped DN still
// compares equal to the entry it names. What does not pass through is the
// asterisk in a DN like `uid=x*,ou=people,dc=corp,dc=example` — which,
// spliced raw into `(member={{user_dn}})`, turns a membership test into a
// prefix match and hands the caller every group whose member happens to
// start the same way.
func (t template) expandFilter(vars map[string]string) string {
	return t.expandWith(func(_, value string) string {
		return escapeFilterValue(value)
	}, vars)
}

// expandWith is expand with the escaping chosen per placeholder rather
// than once for the whole template.
func (t template) expandWith(escape func(name, value string) string, vars map[string]string) string {
	if len(t.literals) == 0 {
		return ""
	}

	var b strings.Builder

	b.Grow(len(t.raw) + 32)

	for i, lit := range t.literals {
		b.WriteString(lit)

		if i < len(t.holes) {
			name := t.holes[i]
			b.WriteString(escape(name, vars[name]))
		}
	}

	return b.String()
}
