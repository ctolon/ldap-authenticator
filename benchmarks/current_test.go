// Package benchmarks measures the parts of the authentication path that
// this package is responsible for.
//
// The directory is in memory, so these numbers say nothing about how fast
// your LDAP server is. That is the point: they measure the overhead this
// library adds on top of a round trip, and a regression in them is a
// regression in this library rather than weather.
package benchmarks

import (
	"context"
	"testing"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

const (
	baseDN   = "dc=example,dc=com"
	peopleDN = "ou=people," + baseDN
	groupsDN = "ou=groups," + baseDN
	aliceDN  = "uid=alice," + peopleDN
	svcDN    = "cn=svc," + baseDN
)

func directory() *ldaptest.Directory {
	return ldaptest.New(
		ldaptest.User(aliceDN, "s3cret").
			With("uid", "alice").
			With("cn", "Alice").
			With("mail", "alice@example.com").
			With("objectClass", "inetOrgPerson").
			With("memberOf", "cn=devs,"+groupsDN),
		ldaptest.User(svcDN, "svcpw").With("objectClass", "person"),
		ldaptest.Group("cn=devs,"+groupsDN).
			With("cn", "devs").
			With("objectClass", "groupOfNames").
			With("member", aliceDN),
	)
}

func build(b *testing.B, opts ...ldapauth.Option) *ldapauth.Client {
	b.Helper()

	base := []ldapauth.Option{
		ldapauth.WithURL("ldap://memory"),
		ldapauth.WithDialer(directory().Dialer()),
	}

	auth, err := ldapauth.New(append(base, opts...)...)
	if err != nil {
		b.Fatalf("New: %v", err)
	}

	b.Cleanup(func() { _ = auth.Close() })

	return auth
}

func BenchmarkDirectBind(b *testing.B) {
	auth := build(b, ldapauth.WithDirectBind("uid={{username}},"+peopleDN))
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if _, err := auth.Authenticate(ctx, "alice", "s3cret"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSearchThenBind(b *testing.B) {
	auth := build(b,
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		ldapauth.WithServiceAccount(svcDN, "svcpw"),
		ldapauth.WithPoolHealthCheck(false),
	)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if _, err := auth.Authenticate(ctx, "alice", "s3cret"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSearchThenBindWithGroups(b *testing.B) {
	auth := build(b,
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		ldapauth.WithServiceAccount(svcDN, "svcpw"),
		ldapauth.WithMemberOfGroups(),
		ldapauth.WithEmailAttribute("mail"),
		ldapauth.WithPoolHealthCheck(false),
	)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if _, err := auth.Authenticate(ctx, "alice", "s3cret"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCachedAuthentication(b *testing.B) {
	auth := build(b,
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithCache(time.Minute),
	)
	ctx := context.Background()

	if _, err := auth.Authenticate(ctx, "alice", "s3cret"); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if _, err := auth.Authenticate(ctx, "alice", "s3cret"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParallelAuthentication(b *testing.B) {
	auth := build(b,
		ldapauth.WithUserSearch(peopleDN, "(uid={{username}})"),
		ldapauth.WithServiceAccount(svcDN, "svcpw"),
		ldapauth.WithPoolHealthCheck(false),
	)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := auth.Authenticate(ctx, "alice", "s3cret"); err != nil {
				b.Fatal(err)
			}
		}
	})
}
