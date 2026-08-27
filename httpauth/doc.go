// Package httpauth turns an [ldapauth.Authenticator] into HTTP
// authentication: middleware for net/http, a login handler, and the policy
// core that the Gin, Echo, and Fiber modules under contrib/ are built on.
//
// It lives in the root module because it needs nothing outside the
// standard library, so nothing about it costs the root module its
// one-dependency promise. The framework modules are separate because they
// do not: importing this package never puts Gin in your build graph.
//
//	mux := http.NewServeMux()
//	mux.Handle("/private", httpauth.BasicAuth(auth)(privateHandler))
//
// Everything a caller might want to vary — the realm, which groups are
// required, what a rejection looks like on the wire, how long an answer
// must take — is an [Option].
//
// # What it does not do
//
// It issues no session and no token. [LoginHandler] verifies the
// credentials and hands you the identity; what that becomes is your
// application's decision.
//
// That is not an omission. How long a session lives, where it is stored,
// what else it carries, how it is revoked, and what happens when the
// directory says the user is gone are all decisions an application has
// already made or is about to, and a library that made them for you would
// be a library you had to work around. Every session library in Go takes a
// user identifier and some claims; that is what you have been handed.
//
// # Status codes
//
//	400  the request was not a login: no username, an empty password
//	401  wrong or absent credentials, with a WWW-Authenticate challenge
//	403  the credentials were right and the groups were not
//	503  the directory could not answer
//
// The distinction between 401 and 403 is the one that matters to a client:
// 401 says try other credentials, 403 says do not bother. [Status] is that
// mapping, exported, so an adapter for another framework does not have to
// reconstruct it from the sentinels.
//
// Bodies are empty by default. A rejection that explains itself is a
// rejection that helps somebody guess, and the error text can name the
// account. [WithErrorHandler] replaces that when your API has a shape of
// its own.
//
// # Timing
//
// A search that matches nothing returns sooner than a search that matches
// and then binds, and that difference is measurable over a network — an
// account enumeration oracle that no amount of collapsing error messages
// will close. [WithMinimumDuration] pads every answer to a floor, which
// moves the difference below the noise of the network in front of it. It
// is not a constant-time guarantee, and nothing built on a directory round
// trip can be.
package httpauth
