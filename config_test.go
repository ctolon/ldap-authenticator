package ldapauth_test

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

// mustFail asserts that a configuration is rejected, and that it is
// rejected with the sentinel a caller would branch on. Every one of these
// is a mistake somebody will make in a configuration file, and the point
// of catching them in New is that the error arrives at startup with the
// name of the option in it, rather than at 3am as a failed login.
func mustFail(t *testing.T, want error, opts ...ldapauth.Option) {
	t.Helper()

	auth, err := ldapauth.New(opts...)
	if err == nil {
		_ = auth.Close()

		t.Fatal("New succeeded, want a validation error")
	}

	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func TestNewRejectsAMissingURL(t *testing.T) {
	t.Parallel()

	mustFail(t, ldapauth.ErrInvalidOption,
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
	)
}

func TestNewRejectsAMissingStrategy(t *testing.T) {
	t.Parallel()

	mustFail(t, ldapauth.ErrInvalidOption,
		ldapauth.WithURL("ldaps://dc.example.com"),
	)
}

func TestNewRejectsBothStrategies(t *testing.T) {
	t.Parallel()

	mustFail(t, ldapauth.ErrInvalidOption,
		ldapauth.WithURL("ldaps://dc.example.com"),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		ldapauth.WithServiceAccount(serviceDN, servicePassword),
	)
}

func TestNewRejectsPlaintextWithoutAnExplicitOptOut(t *testing.T) {
	t.Parallel()

	// A simple bind puts the password on the wire with no encoding at
	// all. Refusing this by default is the whole reason the opt-out has
	// the name it has.
	mustFail(t, ldapauth.ErrTLSRequired,
		ldapauth.WithURL("ldap://dc.example.com"),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
	)
}

func TestPlaintextIsAllowedWithStartTLS(t *testing.T) {
	t.Parallel()

	auth, err := ldapauth.New(
		ldapauth.WithURL("ldap://dc.example.com"),
		ldapauth.WithStartTLS(),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_ = auth.Close()
}

func TestLDAPSAndUnixSocketsNeedNoOptOut(t *testing.T) {
	t.Parallel()

	for _, url := range []string{"ldaps://dc.example.com:636", "ldapi://%2Fvar%2Frun%2Fldapi"} {
		auth, err := ldapauth.New(
			ldapauth.WithURL(url),
			ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		)
		if err != nil {
			t.Errorf("New with %s: %v", url, err)

			continue
		}

		_ = auth.Close()
	}
}

func TestNewRejectsAnUnsupportedScheme(t *testing.T) {
	t.Parallel()

	for _, url := range []string{"https://dc.example.com", "dc.example.com", "://nope"} {
		mustFail(t, ldapauth.ErrInvalidOption,
			ldapauth.WithURL(url),
			ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		)
	}
}

func TestNewRejectsABindTemplateWithoutAUsername(t *testing.T) {
	t.Parallel()

	// Without the placeholder every login would bind as the same DN, and
	// the first correct password anybody typed would authenticate
	// everybody.
	mustFail(t, ldapauth.ErrInvalidOption,
		ldapauth.WithURL("ldaps://dc.example.com"),
		ldapauth.WithDirectBind("cn=service,dc=example,dc=com"),
	)
}

func TestNewRejectsASearchWithoutAServiceAccount(t *testing.T) {
	t.Parallel()

	mustFail(t, ldapauth.ErrInvalidOption,
		ldapauth.WithURL("ldaps://dc.example.com"),
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
	)
}

func TestNewRejectsAnEmptyServiceAccountPassword(t *testing.T) {
	t.Parallel()

	// An empty password on a service account is an anonymous bind wearing
	// a service account's name.
	mustFail(t, ldapauth.ErrInvalidOption,
		ldapauth.WithURL("ldaps://dc.example.com"),
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		ldapauth.WithServiceAccount(serviceDN, ""),
	)
}

func TestNewRejectsContradictoryServiceBinds(t *testing.T) {
	t.Parallel()

	mustFail(t, ldapauth.ErrInvalidOption,
		ldapauth.WithURL("ldaps://dc.example.com"),
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		ldapauth.WithServiceAccount(serviceDN, servicePassword),
		ldapauth.WithAnonymousServiceBind(),
	)
}

func TestNewRejectsOutOfRangeNumbers(t *testing.T) {
	t.Parallel()

	cases := map[string]ldapauth.Option{
		"negative dial timeout":      ldapauth.WithDialTimeout(-time.Second),
		"zero dial timeout":          ldapauth.WithDialTimeout(0),
		"negative request timeout":   ldapauth.WithRequestTimeout(-time.Second),
		"pool size below one":        ldapauth.WithPoolSize(0),
		"negative pool idle":         ldapauth.WithPoolMinIdle(-1),
		"negative retries":           ldapauth.WithRetry(-1),
		"username length below one":  ldapauth.WithUsernameMaxLength(0),
		"cache size below one":       ldapauth.WithCacheSize(0),
		"cache TTL above the cap":    ldapauth.WithCache(time.Hour),
		"negative cache above cap":   ldapauth.WithNegativeCache(time.Hour),
		"nested group depth of zero": ldapauth.WithNestedGroupDepth(0),
		"invalid search scope":       ldapauth.WithUserSearchScope(99),
		"backoff max below base":     ldapauth.WithRetryBackoff(time.Second, time.Millisecond, 2),
		"backoff multiplier below 1": ldapauth.WithRetryBackoff(time.Second, time.Minute, 0.5),
		"tls below 1.2":              ldapauth.WithMinTLSVersion(tls.VersionTLS10),
		"nil logger":                 ldapauth.WithLogger(nil),
		"nil metrics":                ldapauth.WithMetrics(nil),
		"nil clock":                  ldapauth.WithClock(nil),
		"nil dialer":                 ldapauth.WithDialer(nil),
		"empty url":                  ldapauth.WithURL("  "),
		"empty attribute":            ldapauth.WithEmailAttribute(""),
	}

	for name, opt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mustFail(t, ldapauth.ErrInvalidOption,
				ldapauth.WithURL("ldaps://dc.example.com"),
				ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
				opt,
			)
		})
	}
}

func TestNewRejectsPoolMinIdleAbovePoolSize(t *testing.T) {
	t.Parallel()

	mustFail(t, ldapauth.ErrInvalidOption,
		ldapauth.WithURL("ldaps://dc.example.com"),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithPoolSize(2),
		ldapauth.WithPoolMinIdle(3),
	)
}

func TestNewRejectsAGroupSearchWithoutABase(t *testing.T) {
	t.Parallel()

	mustFail(t, ldapauth.ErrInvalidOption,
		ldapauth.WithURL("ldaps://dc.example.com"),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithGroupSearch("", "(member={{user_dn}})"),
	)
}

func TestNewRejectsANilOption(t *testing.T) {
	t.Parallel()

	mustFail(t, ldapauth.ErrInvalidOption,
		ldapauth.WithURL("ldaps://dc.example.com"),
		nil,
	)
}

func TestTLSOptionsCompose(t *testing.T) {
	t.Parallel()

	auth, err := ldapauth.New(
		ldapauth.WithURL("ldaps://dc.example.com"),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithServerName("dc.example.com"),
		ldapauth.WithMinTLSVersion(tls.VersionTLS13),
		ldapauth.WithInsecureSkipVerify(),
		ldapauth.WithLogger(slog.New(slog.DiscardHandler)),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_ = auth.Close()
}

func TestRootCAFileMustExist(t *testing.T) {
	t.Parallel()

	mustFail(t, ldapauth.ErrInvalidOption,
		ldapauth.WithURL("ldaps://dc.example.com"),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithRootCAFile("/nonexistent/ca.pem"),
	)
}

func TestValidationErrorsNameTheOption(t *testing.T) {
	t.Parallel()

	_, err := ldapauth.New(
		ldapauth.WithURL("ldaps://dc.example.com"),
		ldapauth.WithDirectBind("uid={{userid}},"+peopleDN),
	)
	if err == nil {
		t.Fatal("New succeeded with an unknown placeholder")
	}

	if !strings.Contains(err.Error(), "WithDirectBind") {
		t.Errorf("error %q does not name the option that is wrong", err)
	}
}

func TestStatsOnAFreshAuthenticator(t *testing.T) {
	t.Parallel()

	auth := searchAuth(t, newDirectory())

	stats := auth.Stats(testContext(t))

	if stats.Servers != 1 {
		t.Errorf("Servers = %d, want 1", stats.Servers)
	}

	if stats.HealthyServers != 1 {
		t.Errorf("HealthyServers = %d, want 1", stats.HealthyServers)
	}

	if stats.PoolSize != ldapauth.DefaultPoolSize {
		t.Errorf("PoolSize = %d, want the default %d", stats.PoolSize, ldapauth.DefaultPoolSize)
	}

	if stats.PoolInUse != 0 {
		t.Errorf("PoolInUse = %d, want 0", stats.PoolInUse)
	}
}
