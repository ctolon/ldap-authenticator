package ldapauth

// The escaping and template code is unexported, and it is the code most
// worth testing directly: everything else in the package is a
// rearrangement of round trips, but this is where a mistake is a
// vulnerability. Testing it through the public API would mean asserting on
// filter strings recovered from a fake directory, which is a slower way of
// asking the same question with more that can go wrong in between.

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestEscapeFilterValue(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"alice":     "alice",
		"*":         `\2a`,
		"*)(uid=*":  `\2a\29\28uid=\2a`,
		`a\b`:       `a\5cb`,
		"a(b)c":     `a\28b\29c`,
		"\x00":      `\00`,
		"héllo":     `h\c3\a9llo`,
		"":          "",
		"a b":       "a b",
		"cn=x,dc=y": "cn=x,dc=y",
	}

	for in, want := range cases {
		if got := escapeFilterValue(in); got != want {
			t.Errorf("escapeFilterValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEscapeDNValue(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"alice":           "alice",
		"a,b":             `a\,b`,
		"a+b":             `a\+b`,
		`a"b`:             `a\"b`,
		`a\b`:             `a\\b`,
		"a<b>c":           `a\<b\>c`,
		"a;b":             `a\;b`,
		"#lead":           `\#lead`,
		" lead":           `\ lead`,
		"trail ":          `trail\ `,
		"mid # fine":      "mid # fine",
		"\x00":            `\00`,
		"":                "",
		"admin,ou=admins": `admin\,ou=admins`,
	}

	for in, want := range cases {
		if got := escapeDNValue(in); got != want {
			t.Errorf("escapeDNValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEscapedDNParsesBackToOneComponent(t *testing.T) {
	t.Parallel()

	// The property that matters: whatever the username was, the DN it is
	// spliced into has exactly the components the template had. A username
	// that added a component would be a username that moved the entry into
	// another subtree.
	hostile := []string{
		"alice",
		"admin,ou=admins,dc=example,dc=com",
		`a\,b`,
		"a+b",
		`x"y`,
		"#hash",
		" space ",
		"semi;colon",
	}

	for _, username := range hostile {
		dn := "uid=" + escapeDNValue(username) + ",ou=people,dc=example,dc=com"

		parsed, err := ldap.ParseDN(dn)
		if err != nil {
			t.Errorf("username %q produced an unparseable DN %q: %v", username, dn, err)

			continue
		}

		if len(parsed.RDNs) != 4 {
			t.Errorf("username %q produced %d RDNs in %q, want 4", username, len(parsed.RDNs), dn)

			continue
		}

		if got := parsed.RDNs[0].Attributes[0].Value; got != username {
			t.Errorf("username %q round-tripped as %q", username, got)
		}
	}
}

func TestParseTemplate(t *testing.T) {
	t.Parallel()

	t.Run("expands placeholders", func(t *testing.T) {
		t.Parallel()

		tmpl, err := parseTemplate("uid={{username}},ou=people,{{base_dn}}", placeholderUsername, placeholderBaseDN)
		if err != nil {
			t.Fatalf("parseTemplate: %v", err)
		}

		got := tmpl.expand(verbatim, map[string]string{
			placeholderUsername: "alice",
			placeholderBaseDN:   "dc=example,dc=com",
		})

		if want := "uid=alice,ou=people,dc=example,dc=com"; got != want {
			t.Errorf("expand = %q, want %q", got, want)
		}
	})

	t.Run("accepts the %s spelling", func(t *testing.T) {
		t.Parallel()

		// Most LDAP configuration in the wild is written with %s, and
		// making people rewrite it to adopt this package would buy
		// nothing.
		tmpl, err := parseTemplate("uid=%s,ou=people,dc=example,dc=com", placeholderUsername)
		if err != nil {
			t.Fatalf("parseTemplate: %v", err)
		}

		if !tmpl.requires(placeholderUsername) {
			t.Fatal("the printf-style shorthand did not become a username placeholder")
		}
	})

	t.Run("rejects an unknown placeholder", func(t *testing.T) {
		t.Parallel()

		_, err := parseTemplate("uid={{userid}}", placeholderUsername)
		if !errors.Is(err, ErrInvalidOption) {
			t.Fatalf("err = %v, want ErrInvalidOption", err)
		}

		if !strings.Contains(err.Error(), "userid") {
			t.Errorf("error %q does not name the offending placeholder", err)
		}
	})

	t.Run("rejects a template with no placeholder", func(t *testing.T) {
		t.Parallel()

		if _, err := parseTemplate("cn=fixed,dc=example", placeholderUsername); !errors.Is(err, ErrInvalidOption) {
			t.Fatalf("err = %v, want ErrInvalidOption", err)
		}
	})

	t.Run("rejects an unclosed placeholder", func(t *testing.T) {
		t.Parallel()

		if _, err := parseTemplate("uid={{username", placeholderUsername); !errors.Is(err, ErrInvalidOption) {
			t.Fatalf("err = %v, want ErrInvalidOption", err)
		}
	})

	t.Run("rejects an empty template", func(t *testing.T) {
		t.Parallel()

		if _, err := parseTemplate("", placeholderUsername); !errors.Is(err, ErrInvalidOption) {
			t.Fatalf("err = %v, want ErrInvalidOption", err)
		}
	})
}

func TestExpandFilterEscapesValuesAndNotDNs(t *testing.T) {
	t.Parallel()

	tmpl, err := parseTemplate(
		"(&(uid={{username}})(member={{user_dn}}))",
		placeholderUsername, placeholderUserDN,
	)
	if err != nil {
		t.Fatalf("parseTemplate: %v", err)
	}

	got := tmpl.expandFilter(map[string]string{
		placeholderUsername: "a*b",
		placeholderUserDN:   "uid=alice,ou=people,dc=example,dc=com",
	})

	want := `(&(uid=a\2ab)(member=uid=alice,ou=people,dc=example,dc=com))`
	if got != want {
		t.Errorf("expandFilter = %q, want %q", got, want)
	}
}

func TestRetriableClassification(t *testing.T) {
	t.Parallel()

	retriableCases := []error{
		ldap.NewError(ldap.ErrorNetwork, errors.New("connection refused")),
		ldap.NewError(ldap.LDAPResultBusy, errors.New("busy")),
		ldap.NewError(ldap.LDAPResultUnavailable, errors.New("unavailable")),
		ErrNoServerAvailable,
	}

	for _, err := range retriableCases {
		if !retriable(err) {
			t.Errorf("retriable(%v) = false, want true", err)
		}
	}

	final := []error{
		nil,
		ErrInvalidCredentials,
		ErrEmptyPassword,
		ErrInvalidUsername,
		ErrAmbiguousUser,
		ErrClosed,
		ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("nope")),
		ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("nope")),
	}

	for _, err := range final {
		if retriable(err) {
			t.Errorf("retriable(%v) = true, want false", err)
		}
	}
}
