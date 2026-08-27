package ldapauth

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

// The seeds are the same for every target: usernames as they arrive from a
// login form, including the ones that are trying something.
var fuzzSeeds = []string{
	"",
	"alice",
	"*",
	"*)(uid=*",
	"alice)(|(uid=*",
	`alice\`,
	`\2a`,
	"admin,ou=admins,dc=example,dc=com",
	"a+b",
	`a"b`,
	"#hash",
	" leading",
	"trailing ",
	"semi;colon",
	"nul\x00byte",
	"newline\n",
	"héllo",
	"日本語",
	strings.Repeat("a", 1024),
	"\xff\xfe",
}

// FuzzEscapeFilterValue asserts the property the filter escaper exists
// for: whatever goes in, what comes out contributes no structure to the
// filter it is spliced into.
func FuzzEscapeFilterValue(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, username string) {
		escaped := escapeFilterValue(username)

		for i := 0; i < len(escaped); i++ {
			switch escaped[i] {
			case '(', ')', '*':
				t.Fatalf("escapeFilterValue(%q) = %q, which still carries filter structure", username, escaped)
			case '\\':
				// A backslash must introduce a two-digit hex escape and
				// nothing else; a lone one would let the next character
				// mean something.
				if i+2 >= len(escaped) || !isHex(escaped[i+1]) || !isHex(escaped[i+2]) {
					t.Fatalf("escapeFilterValue(%q) = %q, which has a dangling backslash", username, escaped)
				}

				i += 2
			}
		}
	})
}

// FuzzEscapeDNValue asserts that an escaped value is exactly one RDN
// value, whatever it contained. This is the property that stops a username
// from moving the entry it names into another subtree.
func FuzzEscapeDNValue(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, username string) {
		// A DN is defined over characters, and a value that is not valid
		// UTF-8 is not one; those are rejected before they reach a
		// template, by checkUsername.
		if !utf8.ValidString(username) || username == "" {
			t.Skip()
		}

		dn := "uid=" + escapeDNValue(username) + ",ou=people,dc=example,dc=com"

		parsed, err := ldap.ParseDN(dn)
		if err != nil {
			t.Fatalf("username %q produced an unparseable DN %q: %v", username, dn, err)
		}

		if len(parsed.RDNs) != 4 {
			t.Fatalf("username %q produced %d RDNs in %q, want 4", username, len(parsed.RDNs), dn)
		}
	})
}

// FuzzParseTemplate asserts that template parsing is total: every input is
// either a template or an error, and never a panic. Templates come from
// configuration files, which is to say from wherever the deployment's
// configuration comes from.
func FuzzParseTemplate(f *testing.F) {
	for _, seed := range []string{
		"uid={{username}},ou=people,dc=example,dc=com",
		"{{username}}@corp.example",
		"uid=%s,ou=people",
		"{{",
		"}}",
		"{{}}",
		"{{username",
		"{{username}}{{base_dn}}",
		"{{ username }}",
		"",
		"{{username}}{{",
		strings.Repeat("{{username}}", 64),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		tmpl, err := parseTemplate(raw, placeholderUsername, placeholderBaseDN, placeholderUserDN)
		if err != nil {
			return
		}

		// A parsed template must render without panicking, and must
		// render the same way twice.
		vars := map[string]string{
			placeholderUsername: "alice",
			placeholderBaseDN:   "dc=example,dc=com",
			placeholderUserDN:   "uid=alice,dc=example,dc=com",
		}

		first := tmpl.expandFilter(vars)
		if second := tmpl.expandFilter(vars); first != second {
			t.Fatalf("expandFilter is not deterministic: %q then %q", first, second)
		}

		if !tmpl.requires(placeholderUsername) &&
			!tmpl.requires(placeholderBaseDN) &&
			!tmpl.requires(placeholderUserDN) {
			t.Fatalf("template %q parsed with no placeholder", raw)
		}
	})
}

// FuzzCheckUsername asserts that whatever is accepted is a string that can
// safely be put into a DN or a filter — no control characters, no NUL, and
// valid UTF-8.
func FuzzCheckUsername(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed)
	}

	cfg := defaultConfig()

	f.Fuzz(func(t *testing.T, username string) {
		if err := cfg.checkUsername(username); err != nil {
			return
		}

		if !utf8.ValidString(username) {
			t.Fatalf("checkUsername accepted invalid UTF-8: %q", username)
		}

		if strings.ContainsRune(username, 0) {
			t.Fatalf("checkUsername accepted a NUL byte: %q", username)
		}

		if len(username) > cfg.usernameMaxLength {
			t.Fatalf("checkUsername accepted %d bytes, over the %d limit", len(username), cfg.usernameMaxLength)
		}
	})
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
