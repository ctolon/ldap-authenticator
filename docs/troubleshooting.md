# Troubleshooting

## The errors you will actually see

### `ldapauth: invalid credentials`

The directory rejected the bind, or the user search matched nothing. The
two are deliberately the same error; see [security.md](security.md).

To tell them apart while debugging, turn on a debug logger — the search and
the bind are logged as separate stages — or call `Lookup`, which does
distinguish a missing user.

### `ldapauth: user search matched more than one entry`

The filter is too loose. Usually a missing `objectClass` term, or a base DN
that spans two subtrees which both contain a `uid=alice`.

The package refuses rather than picking one, because picking one would make
the authenticated identity depend on server-side ordering.

### `ldapauth: TLS required`

A plaintext `ldap://` URL with no StartTLS. Add `WithStartTLS()`, switch to
`ldaps://`, or — knowing what it means — `WithInsecureNoTLS()`.

### `ldapauth: empty password`

Something upstream is sending a blank password. Often a login form that
submits on the first keystroke, or a client retrying with a cleared field.

It is refused before any network call. That is the point: this is the
request that a naive authenticator would answer with "authenticated".

### `ldapauth: no LDAP server available`

Every configured URL failed to dial. The joined error underneath names each
one and why.

Check the obvious things in this order: the port (636 for `ldaps://`, 389
for `ldap://`), the firewall, and the certificate — a TLS handshake failure
arrives here looking much like a connection failure.

### `No Such Object (32)` on a search that should work

Almost always an ACL rather than a missing entry. Many directories answer a
search whose base the bound identity may not see with "no such object"
rather than "insufficient access", so this is what a service account
without read access looks like.

Check it directly:

```sh
ldapsearch -x -H ldaps://dc1.corp.example:636 \
  -D 'cn=readonly,dc=corp,dc=example' -W \
  -b 'ou=people,dc=corp,dc=example' '(uid=alice)' dn
```

If that returns nothing while an admin bind returns the entry, it is the
ACL.

### `Insufficient Access Rights (50)`

The service account may not read what the configuration asks for.
Frequently the group tree rather than the user tree: user search works,
group resolution does not.

### The user authenticates but has no groups

In order of likelihood:

1. No group source is configured. Group resolution is off by default.
2. `WithMemberOfGroups` against a directory with no `memberOf` overlay.
   OpenLDAP does not maintain the attribute unless it is configured to.
   Check with `ldapsearch ... memberOf` against a user you know is in a
   group.
3. `WithActiveDirectoryGroups` against something that is not Active
   Directory. The matching rule is an AD extension, and a directory that
   does not implement it answers with no entries rather than an error.
4. Direct bind with no service account, against a directory that hides the
   group tree from ordinary users. The group search runs with the user's
   own permissions. Add `WithServiceAccount`.
5. The group filter uses `{{user_dn}}` against a `posixGroup`, which lists
   members by name. Use `(memberUid={{username}})`.

### Nested groups are incomplete

There will be a warning in the log naming the group that could not be read
— a nested walk that cannot read a group logs and continues rather than
failing the login. Usually an ACL on part of the group tree.

Also check `WithNestedGroupDepth`, which defaults to 4.

### Logins are slow

Look at `AuthAttempt` timings and `PoolStats` together.

- In-use at the configured pool size means requests are queuing on slots.
- A slow first login after a quiet period, then fast ones, is the pool
  refilling: raise `WithPoolMinIdle`.
- Uniformly slow logins with an idle pool is the directory, not this
  package. Time an `ldapsearch` from the same host to confirm.
- One slow login in every few, with `RetryScheduled` in the metrics, is a
  transport that keeps breaking. Look for an idle timeout in the path
  shorter than `WithPoolMaxLifetime`.

### Account lockouts

This package never retries a rejected credential, so it is not the source.
Look for a client that retries on its own — a mobile app with a stored
password, a service with a stale credential in its configuration.

`WithNegativeCache` blunts it: repeated failures with the same wrong
password are served from memory rather than reaching the directory.

### It works in tests and fails against the real directory

The usual differences, in order:

1. **ACLs.** The in-memory directory has none. A real one hides most of
   itself from most identities.
2. **`memberOf`.** `ldaptest` will report whatever attribute you put in the
   fixture. A real OpenLDAP maintains it only with the overlay.
3. **Case and spacing in DNs.** Directories are forgiving; string
   comparisons in your own code are not. Compare DNs
   case-insensitively.
4. **Result-size limits.** Active Directory truncates a search at 1000
   entries by default, silently. Use `WithPagingSize`.

## Turning the log up

```go
ldapauth.WithLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
    Level: slog.LevelDebug,
})))
```

Debug logs the stages of each attempt: which strategy ran, what was bound,
how many groups were resolved, and each retry with its delay. It logs the
username, or `[redacted]` under `WithUsernameRedaction`. It never logs a
password.

## Reproducing it in a test

If you can reproduce a problem against `ldaptest`, it is a bug in this
package and worth an issue. If you cannot, the difference between the fake
and your directory is where the answer is — and the list above is the usual
place to start looking.
