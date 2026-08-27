package ldapauth

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// The cache secret is used for three different things, and they must not
// be able to stand in for one another.
//
// They very nearly could. Before these existed, the cache key and the seal
// tag were both HMAC-SHA-256 under the same secret over the same shape —
// one string, a NUL, then another:
//
//	key = HMAC(secret, username ‖ 0 ‖ password)
//	tag = HMAC(secret, key      ‖ 0 ‖ value)
//
// which made the login path a signing oracle for the seal. Submitting a
// login whose username is a victim's cache key and whose password is a
// forged cache value produces, in the negative cache, an entry whose key
// is the seal tag for that value under that key. Reading it back and
// writing tag‖value under the victim's key forges an identity — the exact
// attack the seal exists to prevent, reintroduced through the derivation.
//
// Two things stop it, and both are applied because either alone would be
// enough and neither costs anything: the purposes get separate subkeys
// through HKDF, and each MAC input carries its own domain string. A tag
// produced for one purpose is not a valid tag for another, and cannot be
// made into one.
//
// The strings are versioned so that a future change to what a MAC covers
// can retire the old derivation rather than collide with it.
const (
	cacheKeyDomain      = "ldapauth/cache-key/v1"
	cacheSealDomain     = "ldapauth/cache-seal/v1"
	cacheUsernameDomain = "ldapauth/cache-username/v1"
)

// deriveSubkey expands the master cache secret into a subkey bound to one
// purpose.
//
// HKDF rather than a bare HMAC because the master is whatever the caller
// passed to WithCacheSecret: it may be a passphrase, or a value with
// structure, or shorter than a hash. Extract-then-expand is what turns
// that into uniform key material, and it is in the standard library.
func deriveSubkey(master []byte, domain string) ([]byte, error) {
	subkey, err := hkdf.Key(sha256.New, master, nil, domain, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("ldapauth: deriving the %s subkey: %w", domain, err)
	}

	return subkey, nil
}
