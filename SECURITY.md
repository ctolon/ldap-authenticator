# Security

## Reporting a vulnerability

Report privately through GitHub's advisory form:

<https://github.com/ctolon/ldap-authenticator/security/advisories/new>

Not through an issue, and not through a pull request — both are public from
the moment they are opened.

Expect an acknowledgement within three days and an assessment within a
week. If a fix is warranted you will be credited in the advisory and the
changelog, unless you would rather not be.

## Supported versions

The most recent release. Before 1.0 there are no backports: a fix goes into
the next release and the next release is the supported one.

## What this library promises

- A bind is never issued with an empty password, and the request is refused
  before a connection is opened. RFC 4511 makes a zero-length password an
  unauthenticated bind, which a conforming server answers with success.
- Every value interpolated into a search filter is escaped for RFC 4515,
  and every value interpolated into a distinguished name for RFC 4514.
  There is no exported way to interpolate an unescaped value.
- A wrong password and an unknown user produce the same error, so an
  application built on this package cannot become an account enumeration
  oracle by forgetting to collapse them.
- A pooled connection is bound as the service account and is never rebound
  as a user, so a connection cannot carry one request's identity into the
  next.
- A rejected credential is never retried, so this package cannot walk an
  account into a directory's lockout policy.
- A plaintext `ldap://` URL is refused unless StartTLS is configured or
  `WithInsecureNoTLS` is passed explicitly.
- No password reaches a log record, an error message, or the cache. The
  cache key is an HMAC under a per-process random key.

## What it does not promise

It does not make an insecure directory secure. It cannot tell you whether
your service account has more access than it needs, whether your TLS
certificate is verified by anything, or whether the group whose name you
put in an authorisation rule is the group you meant. Nor is it a
constant-time authenticator: `WithMinimumDuration` in the httpauth package
pads a response, but anything built on a network round trip leaks some
timing, and this one does not pretend otherwise.

A password appearing in a log line, an error string, a `Stats` field, or a
cache entry is a vulnerability. Please report it.
