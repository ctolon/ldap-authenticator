package ldapauth

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// The two strategies live behind one shape: given a username and a
// password, produce the DN that was authenticated and the directory entry
// for it, if one was read. Everything after that — attribute mapping,
// group resolution, caching, retry — is the same either way, which is why
// there is no branch on strategy anywhere outside this file.

// resolved is what a strategy returns.
type resolved struct {
	dn string

	// entry is the user's directory entry, or nil when nothing needed to
	// be read.
	entry *ldap.Entry

	// conn is a connection already bound as the user, when the strategy
	// has one to spare for further reads. The caller owns it and must
	// close it.
	conn Conn
}

func (r *resolved) close() {
	if r != nil && r.conn != nil {
		_ = r.conn.Close()
		r.conn = nil
	}
}

// directBind expands the DN template, binds as it, and reads the entry
// over that same connection when there is anything to read.
//
// It is one round trip in the common case and needs no privileged account.
// The username is escaped as an RFC 4514 attribute value on the way into
// the template, so a username of `x,ou=admins` names an entry whose CN
// contains a comma rather than an entry in another subtree.
func (a *Client) directBind(ctx context.Context, username, password string) (*resolved, error) {
	dn := a.cfg.bindDN.expand(escapeDNValue, map[string]string{placeholderUsername: username})

	conn, url, err := a.bindAs(ctx, dn, password)
	if err != nil {
		return nil, err
	}

	out := &resolved{dn: dn, conn: conn}

	if !a.cfg.needsUserEntry() {
		return out, nil
	}

	// A service account, if one is configured, is the right identity for
	// this read: a directory may well let a user bind while not letting
	// them read their own attributes. Without one, the user's own
	// connection is all there is, and that is the point of the direct-bind
	// deployment that has no service account at all.
	if a.pool != nil {
		entry, perr := a.withPooledConn(ctx, func(pooled Conn) (*ldap.Entry, error) {
			return a.readEntry(pooled, dn)
		})
		if perr != nil {
			out.close()

			return nil, perr
		}

		out.entry = entry

		return out, nil
	}

	entry, err := a.readEntry(conn, dn)
	if err != nil {
		out.close()

		return nil, &AuthError{
			Op:         "read entry",
			URL:        url,
			Username:   a.cfg.safeUsername(username),
			ResultCode: resultCode(err),
			Err:        err,
		}
	}

	out.entry = entry

	return out, nil
}

// searchThenBind finds the user with the service account and then verifies
// the password by binding as the DN the search returned.
//
// The user bind gets its own connection, which is closed straight
// afterwards and never returned to the pool. This is the whole reason the
// pool holds only the service identity: a pooled connection rebound as the
// user would answer the next request's searches as that user.
func (a *Client) searchThenBind(ctx context.Context, username, password string) (*resolved, error) {
	entry, err := a.withPooledConn(ctx, func(pooled Conn) (*ldap.Entry, error) {
		return a.searchUser(pooled, username)
	})
	if err != nil {
		return nil, err
	}

	conn, _, err := a.bindAs(ctx, entry.DN, password)
	if err != nil {
		return nil, err
	}

	return &resolved{dn: entry.DN, entry: entry, conn: conn}, nil
}

// searchUser runs the configured user filter and insists on exactly one
// match.
func (a *Client) searchUser(conn Conn, username string) (*ldap.Entry, error) {
	filter := a.cfg.userFilter.expandFilter(map[string]string{
		placeholderUsername: username,
		placeholderBaseDN:   a.cfg.userBaseDN,
	})

	request := ldap.NewSearchRequest(
		a.cfg.userBaseDN,
		a.cfg.userScope,
		a.cfg.userDerefAliases,
		a.cfg.userSizeLimit,
		a.cfg.searchTimeLimit(),
		false,
		filter,
		a.cfg.attributeList(),
		nil,
	)

	result, err := a.search(conn, request)
	if err != nil {
		return nil, &AuthError{
			Op:         "user search",
			Username:   a.cfg.safeUsername(username),
			ResultCode: resultCode(err),
			Err:        err,
		}
	}

	switch len(result.Entries) {
	case 1:
		return result.Entries[0], nil

	case 0:
		// Deliberately the same error the wrong password produces. A
		// caller that could tell "no such user" from "wrong password"
		// would be an account enumeration oracle for anyone who can reach
		// it, and every login form built on this package would have to
		// remember to collapse the two.
		return nil, &AuthError{
			Op:       "user search",
			Username: a.cfg.safeUsername(username),
			Err:      ErrInvalidCredentials,
		}

	default:
		return nil, &AuthError{
			Op:       "user search",
			Username: a.cfg.safeUsername(username),
			Err:      fmt.Errorf("%w: %d entries matched", ErrAmbiguousUser, len(result.Entries)),
		}
	}
}

// readEntry fetches one entry by DN, for the direct-bind path where there
// is nothing to search for.
func (a *Client) readEntry(conn Conn, dn string) (*ldap.Entry, error) {
	request := ldap.NewSearchRequest(
		dn,
		ScopeBaseObject,
		a.cfg.userDerefAliases,
		1,
		a.cfg.searchTimeLimit(),
		false,
		"(objectClass=*)",
		a.cfg.attributeList(),
		nil,
	)

	result, err := a.search(conn, request)
	if err != nil {
		return nil, err
	}

	if len(result.Entries) == 0 {
		// The bind succeeded, so the entry exists; not being able to read
		// it means the bound identity may not see its own attributes.
		// That is a directory permission to fix, not an authentication
		// failure, and the authentication has already succeeded.
		return nil, nil
	}

	return result.Entries[0], nil
}

// bindAs opens a connection and binds it as dn.
//
// The empty-password check has already happened in Authenticate; it is
// repeated here because this is the last point before the password reaches
// the wire, and the cost of the check is a string comparison. See
// ErrEmptyPassword for why an empty password is not merely invalid but
// dangerous.
func (a *Client) bindAs(ctx context.Context, dn, password string) (Conn, string, error) {
	if password == "" {
		return nil, "", ErrEmptyPassword
	}

	conn, url, err := a.servers.dial(ctx, a.dialer)
	if err != nil {
		return nil, "", err
	}

	a.cfg.metrics.ConnOpened(url)

	if err := conn.Bind(dn, password); err != nil {
		_ = conn.Close()
		a.cfg.metrics.ConnClosed("error")

		code := resultCode(err)

		wrapped := error(err)
		if code == ldap.LDAPResultInvalidCredentials || code == ldap.LDAPResultInappropriateAuthentication {
			wrapped = fmt.Errorf("%w: %w", ErrInvalidCredentials, err)
		}

		return nil, url, &AuthError{
			Op:         "bind",
			URL:        url,
			Username:   a.cfg.safeUsername(dn),
			ResultCode: code,
			Err:        wrapped,
		}
	}

	return conn, url, nil
}

// search issues a search, paging it when the configuration asks for
// paging. Paging matters on Active Directory, which caps a search at 1000
// entries by default and truncates rather than erroring past it.
func (a *Client) search(conn Conn, request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if a.cfg.pagingSize > 0 {
		return conn.SearchWithPaging(request, a.cfg.pagingSize)
	}

	return conn.Search(request)
}

// withPooledConn runs fn on a service-account connection and returns it to
// the pool afterwards, closed if fn failed.
func (a *Client) withPooledConn(ctx context.Context, fn func(Conn) (*ldap.Entry, error)) (*ldap.Entry, error) {
	if a.pool == nil {
		return nil, fmt.Errorf("%w: no service connection is configured", ErrInvalidOption)
	}

	conn, err := a.pool.acquire(ctx)
	if err != nil {
		return nil, err
	}

	entry, err := fn(conn)

	a.pool.release(conn, err)

	return entry, err
}

// needsUserEntry reports whether anything downstream will read the user's
// entry: attributes to map, or memberOf groups to resolve.
func (c *config) needsUserEntry() bool {
	return len(c.attributeList()) > 0
}
