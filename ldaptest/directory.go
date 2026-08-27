// Package ldaptest is an in-memory LDAP directory for tests.
//
// It speaks enough of the protocol to be worth testing against: real
// filter parsing, real scopes, real bind semantics — including the one
// that matters most, where a bind with an empty password succeeds as an
// unauthenticated bind exactly as a conforming server would. A fake that
// quietly rejected the empty password would make the test that proves
// this library never sends one pass for the wrong reason.
//
// It is not a server. Nothing here listens on a socket; a Directory hands
// out an [ldapauth.Dialer] whose connections talk to the map directly. For
// tests against a real directory, see the integration suite.
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

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

// Entry is one directory entry.
type Entry struct {
	// DN is the entry's distinguished name.
	DN string

	// Password is what a simple bind as this entry must present. An entry
	// with no password cannot be bound as.
	Password string

	// Attributes are the entry's attributes, keyed by name.
	Attributes map[string][]string
}

// User builds an entry with a password.
func User(dn, password string) *Entry {
	return &Entry{DN: dn, Password: password, Attributes: map[string][]string{}}
}

// Group builds an entry with no password, for a group or any other
// non-bindable object.
func Group(dn string) *Entry {
	return &Entry{DN: dn, Attributes: map[string][]string{}}
}

// With adds attribute values and returns the entry, for chaining.
func (e *Entry) With(name string, values ...string) *Entry {
	if e.Attributes == nil {
		e.Attributes = map[string][]string{}
	}

	e.Attributes[name] = append(e.Attributes[name], values...)

	return e
}

// Values returns the values of an attribute, matched case-insensitively as
// a directory would.
func (e *Entry) Values(name string) []string {
	if strings.EqualFold(name, "dn") || strings.EqualFold(name, "entryDN") {
		return []string{e.DN}
	}

	for key, values := range e.Attributes {
		if strings.EqualFold(key, name) {
			return values
		}
	}

	return nil
}

// A Bind is one recorded bind attempt. The password is recorded because
// the point of recording it is to let a test assert that an empty one was
// never sent.
type Bind struct {
	DN string

	Password string

	URL string
}

// Directory is an in-memory directory. The zero value is not usable; call
// New. A Directory is safe for concurrent use.
type Directory struct {
	mu sync.Mutex

	entries []*Entry

	// down maps a URL to whether dialling it fails, for failover tests.
	down map[string]bool

	binds []Bind

	searches []*ldap.SearchRequest

	opened int

	closed int

	// BindHook, if set, runs before a bind is evaluated. Returning an
	// error makes the bind fail with that error.
	BindHook func(dn, password string) error

	// SearchHook, if set, runs before a search is evaluated.
	SearchHook func(request *ldap.SearchRequest) error

	// DialHook, if set, runs before a connection is created.
	DialHook func(url string) error
}

// New builds a directory holding the given entries.
func New(entries ...*Entry) *Directory {
	return &Directory{
		entries: entries,
		down:    map[string]bool{},
	}
}

// Add adds an entry.
func (d *Directory) Add(entries ...*Entry) *Directory {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.entries = append(d.entries, entries...)

	return d
}

// SetDown makes dialling a URL fail, or stop failing. Use it to take a
// server out from under a running authenticator.
func (d *Directory) SetDown(url string, down bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.down[url] = down
}

// Binds returns every bind the directory has seen, in order.
func (d *Directory) Binds() []Bind {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make([]Bind, len(d.binds))
	copy(out, d.binds)

	return out
}

// Searches returns every search request the directory has seen, in order.
func (d *Directory) Searches() []*ldap.SearchRequest {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make([]*ldap.SearchRequest, len(d.searches))
	copy(out, d.searches)

	return out
}

// Filters returns the filter string of every search, which is usually the
// only part a test cares about.
func (d *Directory) Filters() []string {
	searches := d.Searches()
	out := make([]string, len(searches))

	for i, s := range searches {
		out[i] = s.Filter
	}

	return out
}

// Conns reports how many connections have been opened and closed. A test
// that wants to prove the pool is pooling asserts on the first; one that
// wants to prove it is not leaking asserts they are equal at the end.
func (d *Directory) Conns() (opened, closed int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.opened, d.closed
}

// Reset clears the recorded binds and searches, leaving the entries alone.
func (d *Directory) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.binds = nil
	d.searches = nil
}

// Dialer returns a dialer that connects to this directory whatever URL it
// is given, unless that URL has been marked down with SetDown.
func (d *Directory) Dialer() ldapauth.Dialer { return dialer{dir: d} }

type dialer struct{ dir *Directory }

func (dl dialer) DialContext(ctx context.Context, url string) (ldapauth.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	d := dl.dir

	d.mu.Lock()
	down := d.down[url]
	hook := d.DialHook
	d.mu.Unlock()

	if hook != nil {
		if err := hook(url); err != nil {
			return nil, err
		}
	}

	if down {
		return nil, ldap.NewError(ldap.ErrorNetwork, fmt.Errorf("ldaptest: %s is down", url))
	}

	d.mu.Lock()
	d.opened++
	d.mu.Unlock()

	return &conn{dir: d, url: url}, nil
}

// conn is one connection to the in-memory directory.
type conn struct {
	dir *Directory

	url string

	mu sync.Mutex

	boundDN string

	closed bool
}

// errRejected is what a refused bind reports.
var errRejected = errors.New("ldaptest: bind rejected")

// errDown is what an operation on a connection to a downed server reports.
var errDown = errors.New("ldaptest: server is down")

func (c *conn) Bind(dn, password string) error {
	d := c.dir

	if err := c.alive(); err != nil {
		return err
	}

	d.mu.Lock()
	d.binds = append(d.binds, Bind{DN: dn, Password: password, URL: c.url})
	hook := d.BindHook
	d.mu.Unlock()

	if hook != nil {
		if err := hook(dn, password); err != nil {
			return err
		}
	}

	// RFC 4511 section 4.2: a simple bind with a zero-length password is
	// an unauthenticated bind, and the server answers it with success.
	// This is modelled faithfully because it is the hazard the library
	// exists to sit in front of.
	if password == "" {
		c.setBound("")

		return nil
	}

	entry := d.find(dn)
	if entry == nil || entry.Password == "" || entry.Password != password {
		// The message says nothing about which DN was refused, because a
		// real directory says nothing either — and a test asserting that
		// this library redacts usernames must not be satisfied by an
		// error the fake wrote.
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errRejected)
	}

	c.setBound(dn)

	return nil
}

func (c *conn) Search(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	d := c.dir

	if err := c.alive(); err != nil {
		return nil, err
	}

	d.mu.Lock()
	d.searches = append(d.searches, request)
	hook := d.SearchHook
	d.mu.Unlock()

	if hook != nil {
		if err := hook(request); err != nil {
			return nil, err
		}
	}

	node, err := compileFilter(request.Filter)
	if err != nil {
		return nil, ldap.NewError(ldap.ErrorFilterCompile, err)
	}

	d.mu.Lock()
	entries := make([]*Entry, len(d.entries))
	copy(entries, d.entries)
	d.mu.Unlock()

	result := &ldap.SearchResult{}

	for _, entry := range entries {
		if !inScope(entry.DN, request.BaseDN, request.Scope) {
			continue
		}

		if !node.match(d, entry) {
			continue
		}

		result.Entries = append(result.Entries, project(entry, request.Attributes))

		if request.SizeLimit > 0 && len(result.Entries) > request.SizeLimit {
			return nil, ldap.NewError(ldap.LDAPResultSizeLimitExceeded, fmt.Errorf("ldaptest: size limit"))
		}
	}

	return result, nil
}

func (c *conn) SearchWithPaging(request *ldap.SearchRequest, _ uint32) (*ldap.SearchResult, error) {
	return c.Search(request)
}

func (c *conn) WhoAmI([]ldap.Control) (*ldap.WhoAmIResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ldap.NewError(ldap.ErrorNetwork, fmt.Errorf("ldaptest: connection closed"))
	}

	if c.dir.isDown(c.url) {
		return nil, ldap.NewError(ldap.ErrorNetwork, errDown)
	}

	if c.boundDN == "" {
		return &ldap.WhoAmIResult{}, nil
	}

	return &ldap.WhoAmIResult{AuthzID: "dn:" + c.boundDN}, nil
}

func (c *conn) SetTimeout(time.Duration) {}

func (c *conn) IsClosing() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.closed
}

func (c *conn) Close() error {
	c.mu.Lock()

	if c.closed {
		c.mu.Unlock()

		return nil
	}

	c.closed = true
	c.mu.Unlock()

	c.dir.mu.Lock()
	c.dir.closed++
	c.dir.mu.Unlock()

	return nil
}

// alive reports whether the connection can still carry an operation. A
// server that has been taken down with SetDown breaks the connections that
// were already open to it, which is what a real server going down does and
// what a pool needs to survive.
func (c *conn) alive() error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()

	if closed {
		return ldap.NewError(ldap.ErrorNetwork, fmt.Errorf("ldaptest: connection closed"))
	}

	if c.dir.isDown(c.url) {
		return ldap.NewError(ldap.ErrorNetwork, errDown)
	}

	return nil
}

func (d *Directory) isDown(url string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.down[url]
}

func (c *conn) setBound(dn string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.boundDN = dn
}

func (d *Directory) find(dn string) *Entry {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, entry := range d.entries {
		if strings.EqualFold(entry.DN, dn) {
			return entry
		}
	}

	return nil
}

// chainMatch evaluates the Active Directory chain matching rule: does
// entry reach target by following attr, transitively?
func (d *Directory) chainMatch(entry *Entry, attr, target string) bool {
	seen := map[string]struct{}{}
	frontier := []*Entry{entry}

	for len(frontier) > 0 {
		var next []*Entry

		for _, e := range frontier {
			key := strings.ToLower(e.DN)

			if _, dup := seen[key]; dup {
				continue
			}

			seen[key] = struct{}{}

			for _, value := range e.Values(attr) {
				if strings.EqualFold(value, target) {
					return true
				}

				if child := d.find(value); child != nil {
					next = append(next, child)
				}
			}
		}

		frontier = next
	}

	return false
}

// project returns a copy of the entry carrying only the requested
// attributes, as a directory would.
func project(entry *Entry, wanted []string) *ldap.Entry {
	out := &ldap.Entry{DN: entry.DN}

	for name, values := range entry.Attributes {
		if len(wanted) > 0 && !containsFold(wanted, name) {
			continue
		}

		copied := make([]string, len(values))
		copy(copied, values)

		out.Attributes = append(out.Attributes, &ldap.EntryAttribute{Name: name, Values: copied})
	}

	return out
}

func containsFold(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.EqualFold(s, needle) {
			return true
		}
	}

	return false
}

// inScope applies an LDAP search scope to a DN.
func inScope(dn, base string, scope int) bool {
	if base == "" {
		return true
	}

	dnLower := strings.ToLower(strings.TrimSpace(dn))
	baseLower := strings.ToLower(strings.TrimSpace(base))

	switch scope {
	case ldap.ScopeBaseObject:
		return dnLower == baseLower

	case ldap.ScopeSingleLevel:
		if !strings.HasSuffix(dnLower, ","+baseLower) {
			return false
		}

		return !strings.Contains(strings.TrimSuffix(dnLower, ","+baseLower), ",")

	default:
		return dnLower == baseLower || strings.HasSuffix(dnLower, ","+baseLower)
	}
}
