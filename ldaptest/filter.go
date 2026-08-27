package ldaptest

import (
	"fmt"
	"strconv"
	"strings"
)

// A minimal RFC 4515 filter parser and evaluator.
//
// It exists so that the in-memory directory can answer the filters this
// package's own callers actually write, and — more to the point — so that
// a test can hand it a username full of parentheses and assert that the
// resulting filter still matches exactly one entry. A fake that ignored
// the filter and matched on a field would answer that question by
// construction, which is to say not at all.
//
// Supported: & | !, equality, presence (attr=*), substrings with *,
// escaped \xx values, and extensible matches of the form
// (attr:rule:=value), which the directory evaluates as a transitive walk
// when rule is the Active Directory chain OID.

// ChainOID is LDAP_MATCHING_RULE_IN_CHAIN, the Active Directory matching
// rule for transitive group membership.
const ChainOID = "1.2.840.113556.1.4.1941"

type filterNode interface {
	match(d *Directory, e *Entry) bool
}

type andNode []filterNode

func (n andNode) match(d *Directory, e *Entry) bool {
	for _, child := range n {
		if !child.match(d, e) {
			return false
		}
	}

	return true
}

type orNode []filterNode

func (n orNode) match(d *Directory, e *Entry) bool {
	for _, child := range n {
		if child.match(d, e) {
			return true
		}
	}

	return false
}

type notNode struct{ child filterNode }

func (n notNode) match(d *Directory, e *Entry) bool { return !n.child.match(d, e) }

type itemNode struct {
	attr string

	// rule is the matching rule OID of an extensible match, or empty.
	rule string

	// present is set for (attr=*).
	present bool

	// parts are the substring pieces for a value containing *; a value
	// with no * has exactly one part and is an equality match.
	parts []string

	wildcard bool
}

func (n itemNode) match(d *Directory, e *Entry) bool {
	if n.rule == ChainOID {
		return d.chainMatch(e, n.attr, n.parts[0])
	}

	values := e.Values(n.attr)

	if n.present {
		return len(values) > 0
	}

	for _, v := range values {
		if n.wildcard {
			if substringMatch(v, n.parts) {
				return true
			}

			continue
		}

		if strings.EqualFold(v, n.parts[0]) {
			return true
		}
	}

	return false
}

func substringMatch(value string, parts []string) bool {
	lower := strings.ToLower(value)

	if parts[0] != "" {
		if !strings.HasPrefix(lower, strings.ToLower(parts[0])) {
			return false
		}

		lower = lower[len(parts[0]):]
	}

	last := len(parts) - 1

	for i := 1; i < last; i++ {
		idx := strings.Index(lower, strings.ToLower(parts[i]))
		if idx < 0 {
			return false
		}

		lower = lower[idx+len(parts[i]):]
	}

	if last > 0 && parts[last] != "" {
		return strings.HasSuffix(lower, strings.ToLower(parts[last]))
	}

	return true
}

// compileFilter parses an RFC 4515 filter string into an evaluable tree.
func compileFilter(filter string) (filterNode, error) {
	p := &parser{in: filter}

	node, err := p.parseFilter()
	if err != nil {
		return nil, err
	}

	if p.pos != len(p.in) {
		return nil, fmt.Errorf("ldaptest: trailing input at %d in %q", p.pos, p.in)
	}

	return node, nil
}

type parser struct {
	in  string
	pos int
}

func (p *parser) parseFilter() (filterNode, error) {
	if err := p.expect('('); err != nil {
		return nil, err
	}

	if p.pos >= len(p.in) {
		return nil, fmt.Errorf("ldaptest: truncated filter %q", p.in)
	}

	var (
		node filterNode
		err  error
	)

	switch p.in[p.pos] {
	case '&':
		p.pos++

		children, cerr := p.parseList()
		node, err = andNode(children), cerr

	case '|':
		p.pos++

		children, cerr := p.parseList()
		node, err = orNode(children), cerr

	case '!':
		p.pos++

		child, cerr := p.parseFilter()
		node, err = notNode{child: child}, cerr

	default:
		node, err = p.parseItem()
	}

	if err != nil {
		return nil, err
	}

	if err := p.expect(')'); err != nil {
		return nil, err
	}

	return node, nil
}

func (p *parser) parseList() ([]filterNode, error) {
	var out []filterNode

	for p.pos < len(p.in) && p.in[p.pos] == '(' {
		child, err := p.parseFilter()
		if err != nil {
			return nil, err
		}

		out = append(out, child)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("ldaptest: empty filter list in %q", p.in)
	}

	return out, nil
}

func (p *parser) parseItem() (filterNode, error) {
	start := p.pos

	for p.pos < len(p.in) && p.in[p.pos] != '=' && p.in[p.pos] != ')' {
		p.pos++
	}

	if p.pos >= len(p.in) || p.in[p.pos] != '=' {
		return nil, fmt.Errorf("ldaptest: item with no = in %q", p.in)
	}

	head := p.in[start:p.pos]
	p.pos++

	item := itemNode{attr: head}

	// An extensible match is written attr:oid:=value, and the trailing
	// colon is part of the head because the scan stopped at the '='.
	if colon := strings.Index(head, ":"); colon >= 0 {
		item.attr = head[:colon]
		item.rule = strings.Trim(head[colon:], ":")
	}

	valueStart := p.pos

	for p.pos < len(p.in) && p.in[p.pos] != ')' {
		p.pos++
	}

	// The value is split on '*' *before* unescaping, because an escaped
	// \2a is a literal asterisk in a value and a bare '*' is structure.
	// Unescaping first would turn every escaped asterisk into a wildcard,
	// which is precisely the injection this library escapes to prevent —
	// and a fake that got this backwards would report the attack as
	// working.
	raw := strings.Split(p.in[valueStart:p.pos], "*")

	parts := make([]string, len(raw))

	for i, piece := range raw {
		unescaped, err := unescapeValue(piece)
		if err != nil {
			return nil, err
		}

		parts[i] = unescaped
	}

	switch {
	case len(parts) == 2 && parts[0] == "" && parts[1] == "":
		item.present = true
		item.parts = []string{""}

	case len(parts) > 1:
		item.wildcard = true
		item.parts = parts

	default:
		item.parts = parts
	}

	return item, nil
}

func (p *parser) expect(c byte) error {
	if p.pos >= len(p.in) || p.in[p.pos] != c {
		return fmt.Errorf("ldaptest: expected %q at %d in %q", string(c), p.pos, p.in)
	}

	p.pos++

	return nil
}

// unescapeValue reverses RFC 4515 \xx escaping. A filter value that
// arrives here still escaped is exactly what proves the escaping worked:
// the parentheses in a hostile username come back as literal characters in
// a value, not as structure.
func unescapeValue(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}

	var b strings.Builder

	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])

			continue
		}

		if i+2 >= len(s) {
			return "", fmt.Errorf("ldaptest: truncated escape in %q", s)
		}

		n, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", fmt.Errorf("ldaptest: bad escape in %q: %w", s, err)
		}

		b.WriteByte(byte(n))
		i += 2
	}

	return b.String(), nil
}
