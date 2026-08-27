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
//	{{base_dn}}     the configured user base DN, spliced verbatim
//	{{user_dn}}     the authenticated user's DN (group templates only)
//
// {{base_dn}} and {{user_dn}} are not escaped as values because they are
// not values: they are DNs the deployment configured or the directory
// returned, and escaping them would corrupt their commas. Neither is ever
// derived from user input.
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

// verbatim is the escape function for values that are already DNs and must
// not be escaped as attribute values.
func verbatim(s string) string { return s }

// expandFilter renders a search-filter template, escaping each placeholder
// for what it is: a username is a value and is escaped for RFC 4515, while
// a DN is a DN and is spliced verbatim — escaping it would turn its commas
// into literal characters and the filter would match nothing.
//
// The distinction is safe because the DN placeholders are never caller
// input. {{base_dn}} comes from the configuration, and {{user_dn}} is what
// the directory itself returned for an entry it had already found.
func (t template) expandFilter(vars map[string]string) string {
	return t.expandWith(func(name, value string) string {
		if name == placeholderUsername {
			return escapeFilterValue(value)
		}

		return value
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
