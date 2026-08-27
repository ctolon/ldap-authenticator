package httpauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

var (
	// ErrNoCredentials reports a request that carried no credentials at
	// all: no Authorization header, or a scheme that is not Basic.
	ErrNoCredentials = errors.New("httpauth: request carried no credentials")

	// ErrMalformedRequest reports a login request whose body could not be
	// read as credentials.
	ErrMalformedRequest = errors.New("httpauth: request is not a login")
)

// identityKey is the context key the identity is stored under. It is an
// unexported type so that nothing else can collide with it, and there is
// no option to change it: a caller who wants the identity elsewhere in
// their own context can put it there.
type identityKey struct{}

// IdentityFrom returns the identity the middleware authenticated, if the
// request went through it.
func IdentityFrom(ctx context.Context) (ldapauth.Identity, bool) {
	identity, ok := ctx.Value(identityKey{}).(ldapauth.Identity)

	return identity, ok
}

// MustIdentity returns the authenticated identity and panics if there is
// none. Use it in a handler that is only ever mounted behind BasicAuth,
// where a missing identity is a routing mistake rather than a runtime
// condition.
func MustIdentity(ctx context.Context) ldapauth.Identity {
	identity, ok := IdentityFrom(ctx)
	if !ok {
		panic("httpauth: no identity in context; the handler is not behind BasicAuth")
	}

	return identity
}

// PrincipalFrom returns the identity as the concrete [ldapauth.Principal],
// for the common case where the mapper was not replaced and reading fields
// is nicer than calling accessors. It reports false both when there is no
// identity and when the identity is some other implementation.
func PrincipalFrom(ctx context.Context) (*ldapauth.Principal, bool) {
	identity, ok := IdentityFrom(ctx)
	if !ok {
		return nil, false
	}

	return ldapauth.AsPrincipal(identity)
}

// WithIdentity returns a context carrying the identity, for adapters and
// for tests that need to exercise a handler without a directory behind it.
func WithIdentity(ctx context.Context, identity ldapauth.Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, identity)
}

// BasicAuth returns middleware that authenticates every request with HTTP
// Basic credentials and puts the resulting identity in the request
// context.
//
//	mux.Handle("/private", httpauth.BasicAuth(auth,
//	    httpauth.WithRealm("corp"),
//	    httpauth.RequireAnyGroup("developers", "ops"),
//	)(handler))
//
// The signature is func(http.Handler) http.Handler, which is what chi,
// gorilla/mux, and every other net/http router expect, so there is nothing
// framework-specific about it.
//
// An option that does not validate panics, because a middleware chain is
// built at startup and there is nowhere to return an error to. Use
// [NewPolicy] and [Middleware] if you would rather handle it.
func BasicAuth(auth ldapauth.Authenticator, opts ...Option) func(http.Handler) http.Handler {
	policy, err := NewPolicy(opts...)
	if err != nil {
		panic(err)
	}

	return Middleware(auth, policy)
}

// Middleware is BasicAuth with the policy already resolved.
func Middleware(auth ldapauth.Authenticator, policy *Policy) func(http.Handler) http.Handler {
	if auth == nil {
		panic("httpauth: nil authenticator")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if policy.skip != nil && policy.skip(r) {
				next.ServeHTTP(w, r)

				return
			}

			username, password, ok := r.BasicAuth()
			if !ok {
				policy.Reject(w, r, ErrNoCredentials)

				return
			}

			identity, err := policy.Authenticate(r.Context(), auth, username, password)
			if err != nil {
				policy.Reject(w, r, err)

				return
			}

			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), identity)))
		})
	}
}

// LoginHandler returns a handler that reads credentials from the request
// body and hands the authenticated principal to onSuccess.
//
// It accepts a JSON object, an HTML form, or Basic credentials in the
// Authorization header, whichever the request carries:
//
//	{"username": "alice", "password": "..."}
//	username=alice&password=...
//
// What happens next is onSuccess's business. This package does not issue a
// session cookie or a token, because the shape of a session is an
// application decision — how long it lives, where it is stored, what else
// it carries — and a library that picked for you would be a library you
// had to work around.
//
//	http.Handle("POST /login", httpauth.LoginHandler(auth,
//	    func(w http.ResponseWriter, r *http.Request, id ldapauth.Identity) {
//	        session.Start(w, id.GetDN(), id.GetGroups())
//	    },
//	))
func LoginHandler(
	auth ldapauth.Authenticator,
	onSuccess func(w http.ResponseWriter, r *http.Request, identity ldapauth.Identity),
	opts ...Option,
) http.HandlerFunc {
	policy, err := NewPolicy(opts...)
	if err != nil {
		panic(err)
	}

	if auth == nil {
		panic("httpauth: nil authenticator")
	}

	if onSuccess == nil {
		panic("httpauth: nil success handler")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		username, password, err := Credentials(r, policy.maxBody)
		if err != nil {
			policy.Reject(w, r, err)

			return
		}

		identity, err := policy.Authenticate(r.Context(), auth, username, password)
		if err != nil {
			policy.Reject(w, r, err)

			return
		}

		onSuccess(w, r.WithContext(WithIdentity(r.Context(), identity)), identity)
	}
}

// Credentials reads a username and password out of a request: from a JSON
// body, a form body, or an Authorization header, whichever is there. The
// body is limited to maxBody bytes.
//
// It is exported because an adapter for another framework needs the same
// parsing, and because getting it wrong — reading an unbounded body, say —
// is a denial of service rather than a bug.
func Credentials(r *http.Request, maxBody int64) (username, password string, err error) {
	if user, pass, ok := r.BasicAuth(); ok {
		return user, pass, nil
	}

	if r.Body == nil {
		return "", "", ErrNoCredentials
	}

	contentType, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")

	switch strings.TrimSpace(strings.ToLower(contentType)) {
	case "application/json", "text/json":
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(io.LimitReader(r.Body, maxBody))

		if err := decoder.Decode(&body); err != nil {
			return "", "", ErrMalformedRequest
		}

		return body.Username, body.Password, nil

	case "application/x-www-form-urlencoded", "multipart/form-data":
		r.Body = http.MaxBytesReader(nil, r.Body, maxBody)

		if err := r.ParseForm(); err != nil {
			return "", "", ErrMalformedRequest
		}

		return r.PostFormValue("username"), r.PostFormValue("password"), nil

	default:
		return "", "", ErrNoCredentials
	}
}
