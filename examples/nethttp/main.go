// Command nethttp is an HTTP server that authenticates against LDAP, using
// the httpauth package. It runs against the in-memory directory by
// default, so it starts with no directory anywhere:
//
//	go run ./examples/nethttp
//	curl -u alice:s3cret localhost:8080/private
//	curl -d '{"username":"alice","password":"s3cret"}' \
//	     -H 'Content-Type: application/json' localhost:8080/login
//
// Point it at a real directory with -url and -bind-dn. The middleware
// signature is func(http.Handler) http.Handler, so it drops into chi,
// gorilla/mux, or a bare ServeMux unchanged.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
	"github.com/ctolon/ldap-authenticator/httpauth"
	"github.com/ctolon/ldap-authenticator/ldaptest"
)

func main() {
	var (
		addr     = flag.String("addr", ":8080", "address to listen on")
		url      = flag.String("url", "", "directory URL; empty uses the in-memory directory")
		bindDN   = flag.String("bind-dn", "uid={{username}},ou=people,dc=example,dc=com", "bind DN template")
		group    = flag.String("require-group", "", "group required to reach /private")
		insecure = flag.Bool("insecure", false, "skip certificate verification (development only)")
	)

	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	auth, err := build(*url, *bindDN, *insecure, logger)
	if err != nil {
		logger.Error("configuration", "error", err)
		os.Exit(1)
	}

	defer func() { _ = auth.Close() }()

	policy := []httpauth.Option{
		httpauth.WithRealm("example"),

		// Pad every answer to the same floor, so that the time a
		// rejection takes says nothing about whether the account exists.
		httpauth.WithMinimumDuration(100 * time.Millisecond),
	}

	if *group != "" {
		policy = append(policy, httpauth.RequireAnyGroup(*group))
	}

	mux := http.NewServeMux()

	mux.Handle("GET /private", httpauth.BasicAuth(auth, policy...)(http.HandlerFunc(private)))

	mux.Handle("POST /login", httpauth.LoginHandler(auth, loggedIn, policy...))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		// Readiness, not liveness: a directory that is down is a reason
		// to stop taking traffic, not a reason to restart.
		if err := auth.HealthCheck(r.Context()); err != nil {
			http.Error(w, "directory unavailable", http.StatusServiceUnavailable)

			return
		}

		_, _ = w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {
		<-ctx.Done()

		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = server.Shutdown(shutdown)
	}()

	logger.Info("listening", "addr", *addr)

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("serving", "error", err)
		os.Exit(1)
	}
}

func build(url, bindDN string, insecure bool, logger *slog.Logger) (ldapauth.Authenticator, error) {
	opts := []ldapauth.Option{
		ldapauth.WithDirectBind(bindDN),
		ldapauth.WithMemberOfGroups(),
		ldapauth.WithNestedGroups(),
		ldapauth.WithEmailAttribute("mail"),
		ldapauth.WithDisplayNameAttribute("cn"),
		ldapauth.WithLogger(logger),
	}

	if url == "" {
		logger.Info("no -url given; using the in-memory directory", "user", "alice", "password", "s3cret")

		return ldapauth.New(append(opts,
			ldapauth.WithURL("ldap://in-memory"),
			ldapauth.WithDialer(demoDirectory().Dialer()),
		)...)
	}

	opts = append(opts, ldapauth.WithURL(url))

	if insecure {
		opts = append(opts, ldapauth.WithInsecureSkipVerify())
	}

	return ldapauth.New(opts...)
}

func demoDirectory() *ldaptest.Directory {
	return ldaptest.New(
		ldaptest.User("uid=alice,ou=people,dc=example,dc=com", "s3cret").
			With("uid", "alice").
			With("cn", "Alice Example").
			With("mail", "alice@example.com").
			With("objectClass", "inetOrgPerson").
			With("memberOf", "cn=developers,ou=groups,dc=example,dc=com"),

		ldaptest.Group("cn=developers,ou=groups,dc=example,dc=com").
			With("cn", "developers").
			With("objectClass", "groupOfNames"),
	)
}

func private(w http.ResponseWriter, r *http.Request) {
	identity := httpauth.MustIdentity(r.Context())

	w.Header().Set("Content-Type", "application/json")

	_ = json.NewEncoder(w).Encode(map[string]any{
		"dn":     identity.GetDN(),
		"name":   identity.GetDisplayName(),
		"email":  identity.GetEmail(),
		"groups": identity.GetGroups(),
	})
}

// loggedIn is where an application would start a session. This one only
// says who logged in, because what a session looks like is not a decision
// a library should make for you.
func loggedIn(w http.ResponseWriter, _ *http.Request, identity ldapauth.Identity) {
	w.Header().Set("Content-Type", "application/json")

	_ = json.NewEncoder(w).Encode(map[string]any{
		"authenticated": true,
		"dn":            identity.GetDN(),
		"groups":        identity.GetGroups(),
	})
}
