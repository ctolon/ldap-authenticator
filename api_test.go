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
	New func(...ldapauth.Option) (*ldapauth.Client, error)

	Authenticate func(*ldapauth.Client, context.Context, string, string) (ldapauth.Identity, error)
	Lookup       func(*ldapauth.Client, context.Context, string) (ldapauth.Identity, error)
	HealthCheck  func(*ldapauth.Client, context.Context) error
	Stats        func(*ldapauth.Client, context.Context) ldapauth.Stats
	InvalidateU  func(*ldapauth.Client, context.Context, string) (int, error)
	InvalidateA  func(*ldapauth.Client, context.Context) (int, error)
	Close        func(*ldapauth.Client) error

	GetDN          func(*ldapauth.Principal) string
	GetUsername    func(*ldapauth.Principal) string
	GetDisplayName func(*ldapauth.Principal) string
	GetEmail       func(*ldapauth.Principal) string
	GetGroups      func(*ldapauth.Principal) []string
	GetAttribute   func(*ldapauth.Principal, string) string
	GetAttrValues  func(*ldapauth.Principal, string) []string
	InGroup        func(*ldapauth.Principal, string) bool
	InAnyGroup     func(*ldapauth.Principal, ...string) bool
	InAllGroups    func(*ldapauth.Principal, ...string) bool
	Clone          func(*ldapauth.Principal) ldapauth.Identity

	AsPrincipal    func(ldapauth.Identity) (*ldapauth.Principal, bool)
	NewMemoryCache func(int, func() time.Time) ldapauth.Cache

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
	WithCacheStore    func(ldapauth.Cache) ldapauth.Option
	WithCacheSecret   func([]byte) ldapauth.Option

	// Pluggable behaviour.
	WithPrincipalMapper func(ldapauth.PrincipalMapper) ldapauth.Option
	WithGroupResolver   func(ldapauth.GroupResolver) ldapauth.Option

	// Input handling.
	WithUsernameMaxLength func(int) ldapauth.Option
	WithPasswordMaxLength func(int) ldapauth.Option
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

		Authenticate: (*ldapauth.Client).Authenticate,
		Lookup:       (*ldapauth.Client).Lookup,
		HealthCheck:  (*ldapauth.Client).HealthCheck,
		Stats:        (*ldapauth.Client).Stats,
		InvalidateU:  (*ldapauth.Client).InvalidateUser,
		InvalidateA:  (*ldapauth.Client).InvalidateAll,
		Close:        (*ldapauth.Client).Close,

		GetDN:          (*ldapauth.Principal).GetDN,
		GetUsername:    (*ldapauth.Principal).GetUsername,
		GetDisplayName: (*ldapauth.Principal).GetDisplayName,
		GetEmail:       (*ldapauth.Principal).GetEmail,
		GetGroups:      (*ldapauth.Principal).GetGroups,
		GetAttribute:   (*ldapauth.Principal).GetAttribute,
		GetAttrValues:  (*ldapauth.Principal).GetAttributeValues,
		InGroup:        (*ldapauth.Principal).InGroup,
		InAnyGroup:     (*ldapauth.Principal).InAnyGroup,
		InAllGroups:    (*ldapauth.Principal).InAllGroups,
		Clone:          (*ldapauth.Principal).Clone,

		AsPrincipal:    ldapauth.AsPrincipal,
		NewMemoryCache: ldapauth.NewMemoryCache,

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
		WithCacheStore:    ldapauth.WithCacheStore,
		WithCacheSecret:   ldapauth.WithCacheSecret,

		WithPrincipalMapper: ldapauth.WithPrincipalMapper,
		WithGroupResolver:   ldapauth.WithGroupResolver,

		WithUsernameMaxLength: ldapauth.WithUsernameMaxLength,
		WithPasswordMaxLength: ldapauth.WithPasswordMaxLength,
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

// The interfaces callers implement or receive, asserted here so that a
// change to one of them is as loud as a change to a function signature.
var (
	_ ldapauth.Metrics         = ldapauth.NoopMetrics{}
	_ ldapauth.Identity        = (*ldapauth.Principal)(nil)
	_ ldapauth.Authenticator   = (*ldapauth.Client)(nil)
	_ ldapauth.GroupResolver   = ldapauth.NoGroups{}
	_ ldapauth.Dialer          = (ldapauth.Dialer)(nil)
	_ ldapauth.Conn            = (ldapauth.Conn)(nil)
	_ ldapauth.Cache           = (ldapauth.Cache)(nil)
	_ ldapauth.PrincipalMapper = (ldapauth.PrincipalMapper)(nil)
	_ ldapauth.Searcher        = (ldapauth.Searcher)(nil)
)

// The func adapters, which exist so that a caller can supply behaviour
// without declaring a type. If one of them stops satisfying its interface
// the build breaks here rather than at a call site.
var (
	_ ldapauth.PrincipalMapper = ldapauth.PrincipalMapperFunc(nil)
	_ ldapauth.GroupResolver   = ldapauth.GroupResolverFunc(nil)
	_ ldapauth.Searcher        = ldapauth.SearcherFunc(nil)
)
