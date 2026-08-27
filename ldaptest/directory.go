package ldaptest

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	// DN is the distinguished name the bind was attempted as. It is empty
	// for an anonymous bind.
	DN string

	// Password is what was presented. It is recorded on purpose: the
	// point of recording it is to let a test assert that an empty one was
	// never sent.
	Password string

	// URL is the server the connection was opened to.
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

	paged int

	// BindHook, if set, runs before a bind is evaluated. Returning an
	// error makes the bind fail with that error.
	BindHook func(dn, password string) error

	// SearchHook, if set, runs before a search is evaluated.
	SearchHook func(request *ldap.SearchRequest) error

	// DialHook, if set, runs before a connection is created.
	DialHook func(url string) error

	// BindControlHook, if set, returns the controls a bind should be
	// answered with.
	//
	// It is how a test produces the password policy control that
	// OpenLDAP and 389 Directory Server use to say *why* a credential
	// was refused — an expired password, a locked account, one that must
	// be changed after a reset. Active Directory says the same thing in
	// the error text and needs nothing here.
	BindControlHook func(dn string) []ldap.Control

	// TimeoutHook, if set, is called every time an operation timeout is
	// set on a connection. It is how a test sees the timeout the
	// authenticator narrowed a connection to, which is otherwise
	// invisible and is exactly where one request's deadline can leak
	// into the next.
	TimeoutHook func(timeout time.Duration)

	// ReferralHook, if set, returns the referral URLs a search should be
	// answered with. Return none for an ordinary search.
	//
	// A referral is what a multi-domain Active Directory forest answers
	// when the base DN names a partition that does not hold the object,
	// and it is the failure mode most likely to be mistaken for "no such
	// user". A fake with no way to produce one is a fake that cannot test
	// the handling.
	ReferralHook func(request *ldap.SearchRequest) []string
}

// New builds a directory holding the given entries.
func New(entries ...*Entry) *Directory {
	return &Directory{
		entries: entries,
		down:    map[string]bool{},
	}
}

// Add adds entries, replacing any that already exist under the same DN.
//
// Replacing rather than appending is what a directory does, and it is the
// behaviour a test wants: appending a second entry with the same DN would
// leave the first one shadowing it in every search, and the test would
// fail for a reason that has nothing to do with what it was testing.
func (d *Directory) Add(entries ...*Entry) *Directory {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, entry := range entries {
		replaced := false

		for i, existing := range d.entries {
			if strings.EqualFold(existing.DN, entry.DN) {
				d.entries[i] = entry
				replaced = true

				break
			}
		}

		if !replaced {
			d.entries = append(d.entries, entry)
		}
	}

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

// PagedSearches reports how many searches were issued with a paged
// results control, for a test that wants to know whether WithPagingSize
// reached the wire.
func (d *Directory) PagedSearches() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.paged
}

// Reset clears the recorded binds and searches, leaving the entries alone.
func (d *Directory) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.binds = nil
	d.searches = nil
	d.paged = 0
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

// SimpleBind performs a bind and returns the response controls, which
// makes this connection an [ldapauth.ControlBinder].
//
// The controls come back on the failure as well as on the success, and the
// failure is the interesting one: that is where a directory says the
// password was right but expired.
func (c *conn) SimpleBind(request *ldap.SimpleBindRequest) (*ldap.SimpleBindResult, error) {
	err := c.Bind(request.Username, request.Password)

	c.dir.mu.Lock()
	hook := c.dir.BindControlHook
	c.dir.mu.Unlock()

	result := &ldap.SimpleBindResult{}

	if hook != nil {
		result.Controls = hook(request.Username)
	}

	return result, err
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

	d.mu.Lock()
	referrals := d.ReferralHook
	d.mu.Unlock()

	node, err := compileFilter(request.Filter)
	if err != nil {
		return nil, ldap.NewError(ldap.ErrorFilterCompile, err)
	}

	d.mu.Lock()
	entries := make([]*Entry, len(d.entries))
	copy(entries, d.entries)
	d.mu.Unlock()

	result := &ldap.SearchResult{}

	if referrals != nil {
		result.Referrals = referrals(request)
	}

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
	c.dir.mu.Lock()
	c.dir.paged++
	c.dir.mu.Unlock()

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

// SetTimeout records the timeout, so that a test can assert on it.
func (c *conn) SetTimeout(timeout time.Duration) {
	c.dir.mu.Lock()
	hook := c.dir.TimeoutHook
	c.dir.mu.Unlock()

	if hook != nil {
		hook(timeout)
	}
}

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
		if len(wanted) > 0 && !slices.ContainsFunc(wanted, func(w string) bool { return strings.EqualFold(w, name) }) {
			continue
		}

		copied := make([]string, len(values))
		copy(copied, values)

		out.Attributes = append(out.Attributes, &ldap.EntryAttribute{Name: name, Values: copied})
	}

	return out
}

// parsedDNs memoises DN parsing.
//
// A fake is allowed to be slower than a server, but not so much slower
// that it distorts a benchmark of the code calling it: parsing is the most
// expensive thing this package does, the set of distinct DNs in a test is
// tiny, and they never change.
var parsedDNs sync.Map

func parseDN(dn string) (*ldap.DN, bool) {
	if cached, ok := parsedDNs.Load(dn); ok {
		parsed, ok := cached.(*ldap.DN)

		return parsed, ok
	}

	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		parsedDNs.Store(dn, nil)

		return nil, false
	}

	parsedDNs.Store(dn, parsed)

	return parsed, true
}

// inScope applies an LDAP search scope to a DN.
//
// The comparison goes through go-ldap's own DN parser rather than through
// string suffixes, so that a base written with different spacing or
// escaping than the entry still matches — which is what a real server
// does, and what a fake matching on strings would get wrong in exactly the
// cases a test is written to catch.
func inScope(dn, base string, scope int) bool {
	if base == "" {
		return true
	}

	parsedDN, ok := parseDN(dn)
	if !ok {
		return false
	}

	parsedBase, ok := parseDN(base)
	if !ok {
		return false
	}

	switch scope {
	case ldap.ScopeBaseObject:
		return parsedDN.EqualFold(parsedBase)

	case ldap.ScopeSingleLevel:
		return len(parsedDN.RDNs) == len(parsedBase.RDNs)+1 && parsedBase.AncestorOfFold(parsedDN)

	default:
		return parsedDN.EqualFold(parsedBase) || parsedBase.AncestorOfFold(parsedDN)
	}
}
