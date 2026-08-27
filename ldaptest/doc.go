// Package ldaptest is an in-memory LDAP directory for tests.
//
// It speaks enough of the protocol to be worth testing against: real
// filter parsing, real scopes, real bind semantics — including the one
// that matters most, where a bind with an empty password succeeds as an
// unauthenticated bind exactly as a conforming server would. A fake that
// quietly rejected the empty password would make the test that proves
// this library never sends one pass for the wrong reason.
//
// It is not a server. Nothing here listens on a socket; a [Directory]
// hands out an [ldapauth.Dialer] whose connections talk to the map
// directly. For tests against a real directory, see the integration suite.
//
// # What it will tell you
//
//	dir.Binds()          every bind, in order, with the password it carried
//	dir.Filters()        every search filter, as it went out
//	dir.Searches()       the full search requests
//	dir.Conns()          how many connections were opened and closed
//	dir.PagedSearches()  how many used a paged results control
//
// [Directory.Binds] records the password on purpose: the point of
// recording it is to let a test assert that an empty one was never sent.
//
// # Making things go wrong
//
//	dir.SetDown(url, true)      dialling fails, and live connections break
//	dir.DialHook = ...          fail, count, or delay a dial
//	dir.BindHook = ...          the same for binds
//	dir.SearchHook = ...        and for searches
//	dir.ReferralHook = ...      answer a search with referrals, as a forest does
//	dir.BindControlHook = ...   answer a bind with the password policy control
//
// [Directory.SetDown] also breaks connections that were already open,
// which is what a server going down actually does and what a connection
// pool has to survive.
//
// # What it is not
//
// It is not a validator. It will not check schemas, enforce access
// controls, or complain about an entry with no objectClass. Those are
// exactly the differences that make something work in tests and fail in
// production, which is what the integration suite is for.
//
//	dir := ldaptest.New(
//	    ldaptest.User("uid=alice,ou=people,dc=example,dc=com", "s3cret").
//	        With("uid", "alice").
//	        With("mail", "alice@example.com"),
//	)
//
//	auth, err := ldapauth.New(
//	    ldapauth.WithURL("ldap://memory"),
//	    ldapauth.WithDialer(dir.Dialer()),
//	    ldapauth.WithDirectBind("uid={{username}},ou=people,dc=example,dc=com"),
//	)
package ldaptest
