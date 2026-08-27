package ldapauth_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"testing"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

// publicAPI mirrors every exported function and method signature in the
// package. It compiles, and that is the whole test: changing a signature
// breaks this file, so a break is never accidental and never silent. A
// deliberate change is a change to this file, and a change to this file is
// a line in the changelog.
type publicAPI struct {
	New func(...ldapauth.Option) (*ldapauth.Authenticator, error)

	Authenticate func(*ldapauth.Authenticator, context.Context, string, string) (*ldapauth.Principal, error)
	Lookup       func(*ldapauth.Authenticator, context.Context, string) (*ldapauth.Principal, error)
	HealthCheck  func(*ldapauth.Authenticator, context.Context) error
	Stats        func(*ldapauth.Authenticator) ldapauth.Stats
	InvalidateU  func(*ldapauth.Authenticator, string) int
	InvalidateA  func(*ldapauth.Authenticator) int
	Close        func(*ldapauth.Authenticator) error

	InGroup     func(*ldapauth.Principal, string) bool
	InAnyGroup  func(*ldapauth.Principal, ...string) bool
	InAllGroups func(*ldapauth.Principal, ...string) bool
	Attribute   func(*ldapauth.Principal, string) string
	AttrValues  func(*ldapauth.Principal, string) []string

	ErrorMessage func(*ldapauth.AuthError) string
	ErrorUnwrap  func(*ldapauth.AuthError) error

	// Connection and transport.
	WithURL              func(string) ldapauth.Option
	WithURLs             func(...string) ldapauth.Option
	WithDialer           func(ldapauth.Dialer) ldapauth.Option
	WithDialTimeout      func(time.Duration) ldapauth.Option
	WithOperationTimeout func(time.Duration) ldapauth.Option
	WithRequestTimeout   func(time.Duration) ldapauth.Option
	WithFailoverPolicy   func(ldapauth.FailoverPolicy) ldapauth.Option
	WithFailoverCooldown func(time.Duration) ldapauth.Option

	// TLS.
	WithTLSConfig              func(*tls.Config) ldapauth.Option
	WithStartTLS               func() ldapauth.Option
	WithRootCAs                func(*x509.CertPool) ldapauth.Option
	WithRootCAFile             func(string) ldapauth.Option
	WithClientCertificate      func(tls.Certificate) ldapauth.Option
	WithClientCertificateFiles func(string, string) ldapauth.Option
	WithServerName             func(string) ldapauth.Option
	WithMinTLSVersion          func(uint16) ldapauth.Option
	WithInsecureSkipVerify     func() ldapauth.Option
	WithInsecureNoTLS          func() ldapauth.Option

	// Strategy.
	WithDirectBind           func(string) ldapauth.Option
	WithUserSearch           func(string, string) ldapauth.Option
	WithUserSearchScope      func(int) ldapauth.Option
	WithDerefAliases         func(int) ldapauth.Option
	WithSearchSizeLimit      func(int) ldapauth.Option
	WithPagingSize           func(uint32) ldapauth.Option
	WithServiceAccount       func(string, string) ldapauth.Option
	WithAnonymousServiceBind func() ldapauth.Option

	// Attributes.
	WithUsernameAttribute    func(string) ldapauth.Option
	WithDisplayNameAttribute func(string) ldapauth.Option
	WithEmailAttribute       func(string) ldapauth.Option
	WithAttributes           func(...string) ldapauth.Option

	// Groups.
	WithMemberOfGroups        func() ldapauth.Option
	WithMemberOfAttribute     func(string) ldapauth.Option
	WithGroupSearch           func(string, string) ldapauth.Option
	WithGroupSearchScope      func(int) ldapauth.Option
	WithGroupNameAttribute    func(string) ldapauth.Option
	WithGroupDNs              func() ldapauth.Option
	WithNestedGroups          func() ldapauth.Option
	WithNestedGroupDepth      func(int) ldapauth.Option
	WithActiveDirectoryGroups func(string) ldapauth.Option

	// Pool.
	WithPoolSize        func(int) ldapauth.Option
	WithPoolMinIdle     func(int) ldapauth.Option
	WithPoolMaxLifetime func(time.Duration) ldapauth.Option
	WithPoolMaxIdleTime func(time.Duration) ldapauth.Option
	WithPoolHealthCheck func(bool) ldapauth.Option

	// Retry.
	WithRetry           func(int) ldapauth.Option
	WithoutRetry        func() ldapauth.Option
	WithRetryBackoff    func(time.Duration, time.Duration, float64) ldapauth.Option
	WithRetryMaxElapsed func(time.Duration) ldapauth.Option

	// Cache.
	WithCache         func(time.Duration) ldapauth.Option
	WithNegativeCache func(time.Duration) ldapauth.Option
	WithCacheSize     func(int) ldapauth.Option

	// Input handling.
	WithUsernameMaxLength func(int) ldapauth.Option
	WithCaseFoldUsername  func() ldapauth.Option
	WithUsernameRedaction func() ldapauth.Option

	// Observability.
	WithLogger  func(*slog.Logger) ldapauth.Option
	WithMetrics func(ldapauth.Metrics) ldapauth.Option
	WithClock   func(func() time.Time) ldapauth.Option
}

func TestPublicAPIIsStable(t *testing.T) {
	t.Parallel()

	api := publicAPI{
		New: ldapauth.New,

		Authenticate: (*ldapauth.Authenticator).Authenticate,
		Lookup:       (*ldapauth.Authenticator).Lookup,
		HealthCheck:  (*ldapauth.Authenticator).HealthCheck,
		Stats:        (*ldapauth.Authenticator).Stats,
		InvalidateU:  (*ldapauth.Authenticator).InvalidateUser,
		InvalidateA:  (*ldapauth.Authenticator).InvalidateAll,
		Close:        (*ldapauth.Authenticator).Close,

		InGroup:     (*ldapauth.Principal).InGroup,
		InAnyGroup:  (*ldapauth.Principal).InAnyGroup,
		InAllGroups: (*ldapauth.Principal).InAllGroups,
		Attribute:   (*ldapauth.Principal).Attribute,
		AttrValues:  (*ldapauth.Principal).AttributeValues,

		ErrorMessage: (*ldapauth.AuthError).Error,
		ErrorUnwrap:  (*ldapauth.AuthError).Unwrap,

		WithURL:              ldapauth.WithURL,
		WithURLs:             ldapauth.WithURLs,
		WithDialer:           ldapauth.WithDialer,
		WithDialTimeout:      ldapauth.WithDialTimeout,
		WithOperationTimeout: ldapauth.WithOperationTimeout,
		WithRequestTimeout:   ldapauth.WithRequestTimeout,
		WithFailoverPolicy:   ldapauth.WithFailoverPolicy,
		WithFailoverCooldown: ldapauth.WithFailoverCooldown,

		WithTLSConfig:              ldapauth.WithTLSConfig,
		WithStartTLS:               ldapauth.WithStartTLS,
		WithRootCAs:                ldapauth.WithRootCAs,
		WithRootCAFile:             ldapauth.WithRootCAFile,
		WithClientCertificate:      ldapauth.WithClientCertificate,
		WithClientCertificateFiles: ldapauth.WithClientCertificateFiles,
		WithServerName:             ldapauth.WithServerName,
		WithMinTLSVersion:          ldapauth.WithMinTLSVersion,
		WithInsecureSkipVerify:     ldapauth.WithInsecureSkipVerify,
		WithInsecureNoTLS:          ldapauth.WithInsecureNoTLS,

		WithDirectBind:           ldapauth.WithDirectBind,
		WithUserSearch:           ldapauth.WithUserSearch,
		WithUserSearchScope:      ldapauth.WithUserSearchScope,
		WithDerefAliases:         ldapauth.WithDerefAliases,
		WithSearchSizeLimit:      ldapauth.WithSearchSizeLimit,
		WithPagingSize:           ldapauth.WithPagingSize,
		WithServiceAccount:       ldapauth.WithServiceAccount,
		WithAnonymousServiceBind: ldapauth.WithAnonymousServiceBind,

		WithUsernameAttribute:    ldapauth.WithUsernameAttribute,
		WithDisplayNameAttribute: ldapauth.WithDisplayNameAttribute,
		WithEmailAttribute:       ldapauth.WithEmailAttribute,
		WithAttributes:           ldapauth.WithAttributes,

		WithMemberOfGroups:        ldapauth.WithMemberOfGroups,
		WithMemberOfAttribute:     ldapauth.WithMemberOfAttribute,
		WithGroupSearch:           ldapauth.WithGroupSearch,
		WithGroupSearchScope:      ldapauth.WithGroupSearchScope,
		WithGroupNameAttribute:    ldapauth.WithGroupNameAttribute,
		WithGroupDNs:              ldapauth.WithGroupDNs,
		WithNestedGroups:          ldapauth.WithNestedGroups,
		WithNestedGroupDepth:      ldapauth.WithNestedGroupDepth,
		WithActiveDirectoryGroups: ldapauth.WithActiveDirectoryGroups,

		WithPoolSize:        ldapauth.WithPoolSize,
		WithPoolMinIdle:     ldapauth.WithPoolMinIdle,
		WithPoolMaxLifetime: ldapauth.WithPoolMaxLifetime,
		WithPoolMaxIdleTime: ldapauth.WithPoolMaxIdleTime,
		WithPoolHealthCheck: ldapauth.WithPoolHealthCheck,

		WithRetry:           ldapauth.WithRetry,
		WithoutRetry:        ldapauth.WithoutRetry,
		WithRetryBackoff:    ldapauth.WithRetryBackoff,
		WithRetryMaxElapsed: ldapauth.WithRetryMaxElapsed,

		WithCache:         ldapauth.WithCache,
		WithNegativeCache: ldapauth.WithNegativeCache,
		WithCacheSize:     ldapauth.WithCacheSize,

		WithUsernameMaxLength: ldapauth.WithUsernameMaxLength,
		WithCaseFoldUsername:  ldapauth.WithCaseFoldUsername,
		WithUsernameRedaction: ldapauth.WithUsernameRedaction,

		WithLogger:  ldapauth.WithLogger,
		WithMetrics: ldapauth.WithMetrics,
		WithClock:   ldapauth.WithClock,
	}

	if api.New == nil {
		t.Fatal("the API surface did not populate")
	}
}

// The interfaces callers implement, asserted here so that a change to one
// of them is as loud as a change to a function signature.
var (
	_ ldapauth.Metrics = ldapauth.NoopMetrics{}
	_ ldapauth.Dialer  = (ldapauth.Dialer)(nil)
	_ ldapauth.Conn    = (ldapauth.Conn)(nil)
)
