package ldapauth

import (
	"fmt"
	"strings"
	"unicode/utf8"
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

// escapeFilterValue escapes a value for use inside an RFC 4515 search
// filter. It escapes the set `()*\` and everything outside 0 < c < 0x80,
// which is a superset of what the RFC requires — the wider net costs
// nothing and keeps multi-byte trickery out of the filter entirely.
func escapeFilterValue(s string) string {
	const hex = "0123456789abcdef"

	escapes := 0

	for i := 0; i < len(s); i++ {
		if filterMustEscape(s[i]) {
			escapes++
		}
	}

	if escapes == 0 {
		return s
	}

	buf := make([]byte, 0, len(s)+escapes*2)

	for i := 0; i < len(s); i++ {
		c := s[i]
		if !filterMustEscape(c) {
			buf = append(buf, c)

			continue
		}

		buf = append(buf, '\\', hex[c>>4], hex[c&0xf])
	}

	return string(buf)
}

func filterMustEscape(c byte) bool {
	return c > 0x7f || c == '(' || c == ')' || c == '\\' || c == '*' || c == 0
}

// escapeDNValue escapes a value for use as an RFC 4514 attribute value
// inside a distinguished name.
//
// The package carries its own escaper rather than calling the one in
// go-ldap so that the exact set of escaped characters is pinned by this
// package's tests and cannot drift underneath us on a dependency bump. The
// rules: the set `"+,;<>\` and the NUL byte are always escaped, `#` is
// escaped when it leads, and a space is escaped when it leads or trails.
// Escaping is done with a leading backslash, except for NUL, which RFC 4514
// requires be written as the hex pair \00.
func escapeDNValue(s string) string {
	if s == "" {
		return ""
	}

	var b strings.Builder

	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		c := s[i]

		switch {
		case c == 0:
			b.WriteString(`\00`)
		case c == '"' || c == '+' || c == ',' || c == ';' || c == '<' || c == '>' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '#' && i == 0:
			b.WriteString(`\#`)
		case c == ' ' && (i == 0 || i == len(s)-1):
			b.WriteString(`\ `)
		default:
			b.WriteByte(c)
		}
	}

	return b.String()
}

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
		if !contains(allowed, name) {
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
func (t template) requires(name string) bool { return contains(t.holes, name) }

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

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}

	return false
}

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
