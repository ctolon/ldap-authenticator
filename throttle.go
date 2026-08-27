package ldapauth

import (
	"container/list"
	"strings"
	"sync"
	"time"
)

// throttle refuses an account locally after too many recent failures, so
// that the attempts never reach the directory's own lockout counter.
//
// The threat is specific and it is not brute force. A directory that locks
// an account after five failures is a directory where anybody who knows a
// username can lock that account out, from anywhere, by getting the
// password wrong five times — no access required, no guessing needed, and
// the victim is the one who has to call the help desk. This package
// already refuses to make it worse by retrying a rejected credential; the
// throttle is what stops it being the instrument.
//
// Two things it is not:
//
// It is not a rate limiter. It counts failures for one account, not
// requests from one client, and an attacker spreading attempts across a
// thousand accounts is limited by nothing here. Put a rate limiter in
// front; see docs/production.md.
//
// It is not shared. Each process has its own counters, so a fleet of
// twenty replicas will pass twenty times the threshold through to the
// directory before all of them are blocking. That is still an order of
// magnitude fewer than none, and making it exact would mean a round trip
// to somewhere shared on every failed login — which is a cost paid on the
// attack path to make the attack slightly harder.
type throttle struct {
	attempts int

	window time.Duration

	cooldown time.Duration

	maxEntries int

	now func() time.Time

	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List
}

type throttleEntry struct {
	username string

	// failures counted since windowStarted.
	failures int

	windowStarted time.Time

	// blockedUntil is when the account may be tried again. Zero when it
	// is not blocked.
	blockedUntil time.Time
}

func newThrottle(attempts int, window, cooldown time.Duration, maxEntries int, now func() time.Time) *throttle {
	return &throttle{
		attempts:   attempts,
		window:     window,
		cooldown:   cooldown,
		maxEntries: maxEntries,
		now:        now,
		entries:    make(map[string]*list.Element, maxEntries),
		order:      list.New(),
	}
}

// allow reports whether the account may be tried, and how long is left if
// not.
func (t *throttle) allow(username string) (ok bool, retryAfter time.Duration) {
	key := throttleKey(username)

	t.mu.Lock()
	defer t.mu.Unlock()

	element, found := t.entries[key]
	if !found {
		return true, 0
	}

	entry := element.Value.(*throttleEntry)
	now := t.now()

	if entry.blockedUntil.IsZero() || !now.Before(entry.blockedUntil) {
		return true, 0
	}

	return false, entry.blockedUntil.Sub(now)
}

// fail records a refused attempt, and starts a cooldown once there have
// been enough of them close enough together.
func (t *throttle) fail(username string) {
	key := throttleKey(username)
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	entry := t.entryLocked(key, username)

	// A cooldown that has expired starts the count again rather than
	// continuing it: the point is repeated failure, not lifetime failure.
	if !entry.blockedUntil.IsZero() && !now.Before(entry.blockedUntil) {
		entry.blockedUntil = time.Time{}
		entry.failures = 0
	}

	if entry.windowStarted.IsZero() || now.Sub(entry.windowStarted) > t.window {
		entry.windowStarted = now
		entry.failures = 0
	}

	entry.failures++

	if entry.failures >= t.attempts {
		entry.blockedUntil = now.Add(t.cooldown)
		entry.failures = 0
		entry.windowStarted = time.Time{}
	}
}

// succeed clears an account's history. A correct password is the end of
// the story: whoever was getting it wrong has stopped, or was somebody
// else entirely.
func (t *throttle) succeed(username string) {
	key := throttleKey(username)

	t.mu.Lock()
	defer t.mu.Unlock()

	if element, found := t.entries[key]; found {
		t.removeLocked(element)
	}
}

// entryLocked finds or creates the entry for a key. The caller holds the
// lock.
func (t *throttle) entryLocked(key, username string) *throttleEntry {
	if element, found := t.entries[key]; found {
		return element.Value.(*throttleEntry)
	}

	entry := &throttleEntry{username: username}
	t.entries[key] = t.order.PushBack(entry)

	// Bounded, because the keys come from whatever anybody types into a
	// login form. Evicting the oldest is the right way to lose: an
	// attacker can push a real account's counter out by inventing
	// usernames, and the alternative is a map that grows until the
	// process dies, which is the same attack with a worse ending.
	for len(t.entries) > t.maxEntries {
		oldest := t.order.Front()
		if oldest == nil {
			break
		}

		t.removeLocked(oldest)
	}

	return entry
}

func (t *throttle) removeLocked(element *list.Element) {
	delete(t.entries, throttleKey(element.Value.(*throttleEntry).username))
	t.order.Remove(element)
}

// blocked reports how many accounts are in a cooldown, for Stats.
func (t *throttle) blocked() int {
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	count := 0

	for element := t.order.Front(); element != nil; element = element.Next() {
		entry := element.Value.(*throttleEntry)

		if !entry.blockedUntil.IsZero() && now.Before(entry.blockedUntil) {
			count++
		}
	}

	return count
}

// throttleKey folds case unconditionally.
//
// Unlike the cache, which folds only when asked, the throttle always
// does — because "Alice" and "alice" are the same account to lock out on
// every directory anybody runs, and a throttle that could be walked around
// by changing the capitalisation would be a throttle in name only.
func throttleKey(username string) string { return strings.ToLower(username) }
