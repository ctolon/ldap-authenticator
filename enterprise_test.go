package ldapauth_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

// ---- account state -------------------------------------------------------

// adError builds the error Active Directory returns for a refused bind:
// result code 49, with the real reason as a hexadecimal code in the text.
func adError(data string) error {
	return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New(
		"80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data "+data+", v3839",
	))
}

func TestActiveDirectoryReasonsAreExtracted(t *testing.T) {
	t.Parallel()

	cases := map[string]ldapauth.RejectionReason{
		"525": ldapauth.ReasonNoSuchUser,
		"52e": ldapauth.ReasonBadPassword,
		"530": ldapauth.ReasonTimeRestricted,
		"531": ldapauth.ReasonWorkstationRestricted,
		"532": ldapauth.ReasonPasswordExpired,
		"533": ldapauth.ReasonAccountDisabled,
		"701": ldapauth.ReasonAccountExpired,
		"773": ldapauth.ReasonPasswordMustChange,
		"775": ldapauth.ReasonAccountLocked,
		"52E": ldapauth.ReasonBadPassword,
	}

	for data, want := range cases {
		t.Run(data, func(t *testing.T) {
			t.Parallel()

			dir := newDirectory()
			dir.BindHook = func(dn, _ string) error {
				if dn == aliceDN {
					return adError(data)
				}

				return nil
			}

			auth := directAuth(t, dir, ldapauth.WithoutRetry())

			_, err := auth.Authenticate(testContext(t), "alice", alicePassword)

			// Whatever the reason, the caller gets the same error. That
			// is the point: the reason is for the log, never for the
			// response.
			if !errors.Is(err, ldapauth.ErrInvalidCredentials) {
				t.Fatalf("err = %v, want ErrInvalidCredentials", err)
			}

			if got := ldapauth.ReasonFor(err); got != want {
				t.Errorf("reason = %v, want %v", got, want)
			}
		})
	}
}

func TestADirectoryThatSaysNothingGivesNoReason(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	auth := directAuth(t, dir, ldapauth.WithoutRetry())

	_, err := auth.Authenticate(testContext(t), "alice", "wrong")

	if got := ldapauth.ReasonFor(err); got != ldapauth.ReasonUnspecified {
		t.Errorf("reason = %v, want unspecified: the fake said nothing", got)
	}
}

func TestNonsenseInAnErrorIsNotAReason(t *testing.T) {
	t.Parallel()

	// "data" appears in prose, and a code is three or four hex digits.
	// Anything else must not be read as one.
	for _, text := range []string{
		"the data was rejected",
		"data 12345678",
		"data zz",
		"data ",
	} {
		dir := newDirectory()
		dir.BindHook = func(dn, _ string) error {
			if dn == aliceDN {
				return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New(text))
			}

			return nil
		}

		auth := directAuth(t, dir, ldapauth.WithoutRetry())

		_, err := auth.Authenticate(testContext(t), "alice", alicePassword)

		if got := ldapauth.ReasonFor(err); got != ldapauth.ReasonUnspecified {
			t.Errorf("%q gave reason %v, want unspecified", text, got)
		}
	}
}

func TestReasonActionability(t *testing.T) {
	t.Parallel()

	// The distinction a help desk cares about: trying again might work,
	// or it definitely will not.
	actionable := []ldapauth.RejectionReason{
		ldapauth.ReasonBadPassword,
		ldapauth.ReasonNoSuchUser,
		ldapauth.ReasonUnspecified,
	}

	for _, reason := range actionable {
		if !reason.Actionable() {
			t.Errorf("%v is not actionable, want actionable", reason)
		}
	}

	unactionable := []ldapauth.RejectionReason{
		ldapauth.ReasonAccountDisabled,
		ldapauth.ReasonAccountLocked,
		ldapauth.ReasonAccountExpired,
		ldapauth.ReasonPasswordExpired,
		ldapauth.ReasonPasswordMustChange,
		ldapauth.ReasonTimeRestricted,
		ldapauth.ReasonWorkstationRestricted,
	}

	for _, reason := range unactionable {
		if reason.Actionable() {
			t.Errorf("%v is actionable, want not", reason)
		}
	}
}

func TestReasonForANonAuthError(t *testing.T) {
	t.Parallel()

	if got := ldapauth.ReasonFor(errors.New("something else")); got != ldapauth.ReasonUnspecified {
		t.Errorf("reason = %v, want unspecified", got)
	}

	if got := ldapauth.ReasonFor(nil); got != ldapauth.ReasonUnspecified {
		t.Errorf("reason for nil = %v, want unspecified", got)
	}
}

// ---- referrals -----------------------------------------------------------

func TestAReferralOnlyAnswerIsIgnoredByDefault(t *testing.T) {
	t.Parallel()

	dir := newDirectory()
	dir.ReferralHook = func(request *ldap.SearchRequest) []string {
		if request.BaseDN == peopleDN {
			return []string{"ldap://child.corp.example/dc=child,dc=corp,dc=example"}
		}

		return nil
	}

	auth := searchAuth(t, dir, ldapauth.WithoutRetry())

	// The user is in the partition the referral points at, so the search
	// finds nothing here and the directory says where to look. The
	// default keeps every deployment that upgraded working: a
	// referral-only answer is an empty answer.
	_, err := auth.Authenticate(testContext(t), "elsewhere", alicePassword)
	if !errors.Is(err, ldapauth.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestReferralFailSaysWhatHappened(t *testing.T) {
	t.Parallel()

	const referral = "ldap://child.corp.example/dc=child,dc=corp,dc=example"

	dir := newDirectory()
	dir.ReferralHook = func(request *ldap.SearchRequest) []string {
		if request.BaseDN == peopleDN {
			return []string{referral}
		}

		return nil
	}

	auth := searchAuth(t, dir,
		ldapauth.WithReferralPolicy(ldapauth.ReferralFail),
		ldapauth.WithoutRetry(),
	)

	_, err := auth.Authenticate(testContext(t), "elsewhere", alicePassword)
	if !errors.Is(err, ldapauth.ErrReferral) {
		t.Fatalf("err = %v, want ErrReferral", err)
	}

	var authErr *ldapauth.AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("err = %v, want an *AuthError", err)
	}

	if len(authErr.Referrals) != 1 || authErr.Referrals[0] != referral {
		t.Errorf("Referrals = %v, want [%s]", authErr.Referrals, referral)
	}
}

func TestReferralsAlongsideEntriesAreOrdinary(t *testing.T) {
	t.Parallel()

	// A search that crosses a partition boundary gets continuation
	// references for the parts it did not cover. The entries it did
	// return are still the answer, and failing on them would break every
	// Active Directory deployment there is.
	dir := newDirectory()
	dir.ReferralHook = func(*ldap.SearchRequest) []string {
		return []string{"ldap://child.corp.example/dc=child,dc=corp,dc=example"}
	}

	auth := searchAuth(t, dir, ldapauth.WithReferralPolicy(ldapauth.ReferralFail))

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

// ---- lockout protection --------------------------------------------------

func TestLockoutProtectionStopsReachingTheDirectory(t *testing.T) {
	t.Parallel()

	// The attack: anybody who knows a username can lock that account out
	// of the directory by getting the password wrong often enough. This
	// stops the attempts arriving.
	dir := newDirectory()

	auth := directAuth(t, dir,
		ldapauth.WithLockoutProtection(3, time.Minute, time.Minute),
		ldapauth.WithoutRetry(),
	)

	for range 3 {
		if _, err := auth.Authenticate(testContext(t), "alice", "wrong"); !errors.Is(err, ldapauth.ErrInvalidCredentials) {
			t.Fatalf("err = %v, want ErrInvalidCredentials", err)
		}
	}

	reached := len(dir.Binds())

	for range 10 {
		_, err := auth.Authenticate(testContext(t), "alice", "wrong")
		if !errors.Is(err, ldapauth.ErrTooManyAttempts) {
			t.Fatalf("err = %v, want ErrTooManyAttempts", err)
		}
	}

	if len(dir.Binds()) != reached {
		t.Errorf("binds went from %d to %d: the throttle let attempts through",
			reached, len(dir.Binds()))
	}

	if blocked := auth.Stats(testContext(t)).BlockedAccounts; blocked != 1 {
		t.Errorf("BlockedAccounts = %d, want 1", blocked)
	}
}

func TestTheCooldownExpires(t *testing.T) {
	t.Parallel()

	clock := newClock()
	dir := newDirectory()

	auth := directAuth(t, dir,
		ldapauth.WithClock(clock.Now),
		ldapauth.WithLockoutProtection(2, time.Minute, 30*time.Second),
		ldapauth.WithoutRetry(),
	)

	for range 2 {
		_, _ = auth.Authenticate(testContext(t), "alice", "wrong")
	}

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); !errors.Is(err, ldapauth.ErrTooManyAttempts) {
		t.Fatalf("err = %v, want ErrTooManyAttempts", err)
	}

	clock.Advance(31 * time.Second)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate after the cooldown: %v", err)
	}
}

func TestASuccessClearsTheCount(t *testing.T) {
	t.Parallel()

	dir := newDirectory()

	auth := directAuth(t, dir,
		ldapauth.WithLockoutProtection(3, time.Minute, time.Minute),
		ldapauth.WithoutRetry(),
	)

	for range 2 {
		_, _ = auth.Authenticate(testContext(t), "alice", "wrong")
	}

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// Two more failures must not be enough, because the count started
	// again when the right password arrived.
	for range 2 {
		if _, err := auth.Authenticate(testContext(t), "alice", "wrong"); !errors.Is(err, ldapauth.ErrInvalidCredentials) {
			t.Fatalf("err = %v, want the directory to have been asked", err)
		}
	}
}

func TestAnOutageDoesNotLockAnybodyOut(t *testing.T) {
	t.Parallel()

	// A directory that is unreachable says nothing about whether the
	// password was right. Counting it would mean an outage locking out
	// every account that tried to log in during it.
	dir := newDirectory()
	dir.SetDown(memoryURL, true)

	auth := directAuth(t, dir,
		ldapauth.WithLockoutProtection(2, time.Minute, time.Minute),
		ldapauth.WithoutRetry(),
	)

	for range 5 {
		if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); errors.Is(err, ldapauth.ErrTooManyAttempts) {
			t.Fatal("an outage counted as a failed credential")
		}
	}

	dir.SetDown(memoryURL, false)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate once the directory came back: %v", err)
	}
}

func TestACachedSuccessSurvivesSomebodyElsesGuessing(t *testing.T) {
	t.Parallel()

	// The throttle's own cost is that it refuses the legitimate user
	// along with the attacker. The cache is what buys them out of it, and
	// the ordering that makes that work is worth a test.
	dir := newDirectory()

	auth := directAuth(t, dir,
		ldapauth.WithCache(time.Minute),
		ldapauth.WithLockoutProtection(2, time.Minute, time.Minute),
		ldapauth.WithoutRetry(),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	for range 3 {
		_, _ = auth.Authenticate(testContext(t), "alice", "wrong")
	}

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("the cached user was locked out by somebody else's guessing: %v", err)
	}
}

func TestTheThrottleIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	// An account is one account however it is capitalised, on every
	// directory anybody runs. A throttle that could be walked around with
	// the shift key would be a throttle in name only.
	dir := newDirectory()

	auth := directAuth(t, dir,
		ldapauth.WithLockoutProtection(2, time.Minute, time.Minute),
		ldapauth.WithoutRetry(),
	)

	_, _ = auth.Authenticate(testContext(t), "alice", "wrong")
	_, _ = auth.Authenticate(testContext(t), "ALICE", "wrong")

	if _, err := auth.Authenticate(testContext(t), "Alice", "wrong"); !errors.Is(err, ldapauth.ErrTooManyAttempts) {
		t.Fatalf("err = %v, want ErrTooManyAttempts", err)
	}
}

func TestTheThrottleIsBounded(t *testing.T) {
	t.Parallel()

	// The keys come from a login form, so an attacker inventing usernames
	// must not be able to grow the map until the process dies.
	dir := newDirectory()

	auth := directAuth(t, dir,
		ldapauth.WithLockoutProtection(1, time.Minute, time.Minute),
		ldapauth.WithoutRetry(),
	)

	// Distinct every time. An earlier version of this test built its
	// usernames from i%8 and i%26 and produced two hundred of them, so
	// the bound it was checking was never reached and the eviction path
	// it was meant to exercise never ran.
	const invented = 20000

	for i := range invented {
		_, _ = auth.Authenticate(testContext(t), "invented-"+strconv.Itoa(i), "wrong")
	}

	blocked := auth.Stats(testContext(t)).BlockedAccounts

	if blocked > ldapauth.DefaultLockoutMaxAccounts {
		t.Errorf("BlockedAccounts = %d, want at most the %d the throttle tracks",
			blocked, ldapauth.DefaultLockoutMaxAccounts)
	}

	if blocked < ldapauth.DefaultLockoutMaxAccounts/2 {
		t.Errorf("BlockedAccounts = %d after %d invented usernames; the bound was never reached, so nothing was evicted",
			blocked, invented)
	}

	// And a real account is still protected, even though an attacker
	// pushed thousands of invented ones through the table.
	for range 2 {
		_, _ = auth.Authenticate(testContext(t), "alice", "wrong")
	}

	if _, err := auth.Authenticate(testContext(t), "alice", "wrong"); !errors.Is(err, ldapauth.ErrTooManyAttempts) {
		t.Errorf("err = %v, want alice still throttled", err)
	}
}

func TestTheThrottleIsSafeUnderLoad(t *testing.T) {
	t.Parallel()

	dir := newDirectory()

	auth := directAuth(t, dir,
		ldapauth.WithLockoutProtection(5, time.Minute, time.Second),
		ldapauth.WithoutRetry(),
	)

	var wg sync.WaitGroup

	for i := range 40 {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			password := alicePassword
			if i%2 == 0 {
				password = "wrong"
			}

			_, _ = auth.Authenticate(testContext(t), "alice", password)
		}(i)
	}

	wg.Wait()
}

// ---- cache username hashing ----------------------------------------------

func TestCacheUsernameHashingHidesTheUsername(t *testing.T) {
	t.Parallel()

	store := newRecordingCache()

	auth := searchAuth(t, newDirectory(),
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheStore(store),
		ldapauth.WithCacheUsernameHashing(),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	store.mu.Lock()
	usernames := append([]string(nil), store.usernames...)
	store.mu.Unlock()

	if len(usernames) != 1 {
		t.Fatalf("usernames = %v, want one", usernames)
	}

	if strings.Contains(usernames[0], "alice") {
		t.Errorf("the store was given %q, which carries the username", usernames[0])
	}

	if len(usernames[0]) != 64 {
		t.Errorf("the store was given %d characters, want a 64-character hex digest", len(usernames[0]))
	}
}

func TestInvalidationStillWorksWithHashedUsernames(t *testing.T) {
	t.Parallel()

	// Hashing the username would be useless if it broke the one thing the
	// username is passed for.
	dir := newDirectory()

	auth := searchAuth(t, dir,
		ldapauth.WithCache(time.Minute),
		ldapauth.WithCacheUsernameHashing(),
	)

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	dropped, err := auth.InvalidateUser(testContext(t), "alice")
	if err != nil {
		t.Fatalf("InvalidateUser: %v", err)
	}

	if dropped != 1 {
		t.Fatalf("InvalidateUser dropped %d entries, want 1", dropped)
	}

	before := len(dir.Binds())

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if len(dir.Binds()) == before {
		t.Error("the invalidated entry was still served from cache")
	}
}

func TestHashingWithoutCachingIsAConfigurationError(t *testing.T) {
	t.Parallel()

	mustFail(t, ldapauth.ErrInvalidOption,
		ldapauth.WithURL("ldaps://dc.example.com"),
		ldapauth.WithDirectBind("uid={{username}},"+peopleDN),
		ldapauth.WithCacheUsernameHashing(),
	)
}

// ---- reloadable ----------------------------------------------------------

func TestReloadableSwapsWithoutInterrupting(t *testing.T) {
	t.Parallel()

	first := searchAuth(t, newDirectory())

	reloadable := ldapauth.NewReloadable(first)

	if _, err := reloadable.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// A new client, as a password rotation would build.
	secondDir := newDirectory()
	second := searchAuth(t, secondDir)

	previous := reloadable.Replace(second)

	if previous != first {
		t.Error("Replace did not return the client it replaced")
	}

	if reloadable.Current() != second {
		t.Error("Current did not return the new client")
	}

	if _, err := reloadable.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate after the swap: %v", err)
	}

	if len(secondDir.Binds()) == 0 {
		t.Error("the swap happened but requests still went to the old client")
	}

	// Closing the replaced client is the caller's job, and it must not
	// disturb the one now in use.
	if err := previous.Close(); err != nil {
		t.Fatalf("closing the replaced client: %v", err)
	}

	if _, err := reloadable.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate after closing the old client: %v", err)
	}
}

func TestReloadableIsSafeUnderLoad(t *testing.T) {
	t.Parallel()

	reloadable := ldapauth.NewReloadable(searchAuth(t, newDirectory()))

	stop := make(chan struct{})

	var wg sync.WaitGroup

	for range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for {
				select {
				case <-stop:
					return
				default:
				}

				_, _ = reloadable.Authenticate(context.Background(), "alice", alicePassword)
			}
		}()
	}

	// Swap underneath them, repeatedly, the way a secret manager would.
	for range 20 {
		previous := reloadable.Replace(searchAuth(t, newDirectory()))

		_ = previous.Close()

		time.Sleep(2 * time.Millisecond)
	}

	close(stop)
	wg.Wait()
}

func TestReloadableRefusesNothing(t *testing.T) {
	t.Parallel()

	// A failed reload must leave the working client in place, not install
	// nothing and fail every request afterwards.
	defer func() {
		if recover() == nil {
			t.Error("Replace accepted a nil client")
		}
	}()

	ldapauth.NewReloadable(searchAuth(t, newDirectory())).Replace(nil)
}

// ---- the password policy control -----------------------------------------

// policyControl builds the control OpenLDAP and 389 Directory Server
// return when they are asked for it.
func policyControl(errorCode int8) []ldap.Control {
	control := ldap.NewControlBeheraPasswordPolicy()
	control.Error = errorCode
	control.Expire = -1
	control.Grace = -1

	return []ldap.Control{control}
}

func TestPasswordPolicyReasonsAreExtracted(t *testing.T) {
	t.Parallel()

	cases := map[int8]ldapauth.RejectionReason{
		0: ldapauth.ReasonPasswordExpired,
		1: ldapauth.ReasonAccountLocked,
		2: ldapauth.ReasonPasswordMustChange,

		// Answers to a password *change* rather than to a bind. They say
		// nothing about why a credential was refused.
		6: ldapauth.ReasonUnspecified,
		7: ldapauth.ReasonUnspecified,
		8: ldapauth.ReasonUnspecified,
	}

	for code, want := range cases {
		t.Run(want.String()+"/"+strconv.Itoa(int(code)), func(t *testing.T) {
			t.Parallel()

			dir := newDirectory()
			dir.BindControlHook = func(dn string) []ldap.Control {
				if dn == aliceDN {
					return policyControl(code)
				}

				return nil
			}

			auth := directAuth(t, dir,
				ldapauth.WithPasswordPolicyControl(),
				ldapauth.WithoutRetry(),
			)

			_, err := auth.Authenticate(testContext(t), "alice", "wrong")
			if !errors.Is(err, ldapauth.ErrInvalidCredentials) {
				t.Fatalf("err = %v, want ErrInvalidCredentials", err)
			}

			if got := ldapauth.ReasonFor(err); got != want {
				t.Errorf("reason = %v, want %v", got, want)
			}
		})
	}
}

func TestThePolicyControlIsNotSentUnlessAsked(t *testing.T) {
	t.Parallel()

	// It is off by default because it changes what goes on the wire, and
	// adding an unrequested control to every bind is not a thing to do to
	// somebody without asking.
	asked := false

	dir := newDirectory()
	dir.BindControlHook = func(string) []ldap.Control {
		asked = true

		return policyControl(0)
	}

	auth := directAuth(t, dir, ldapauth.WithoutRetry())

	if _, err := auth.Authenticate(testContext(t), "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if asked {
		t.Error("the password policy control was requested without WithPasswordPolicyControl")
	}
}

func TestAControlBinderIsStillUsedForSuccessfulBinds(t *testing.T) {
	t.Parallel()

	// Switching to SimpleBind must not break the ordinary path.
	dir := newDirectory()

	auth := searchAuth(t, dir, ldapauth.WithPasswordPolicyControl())

	identity, err := auth.Authenticate(testContext(t), "alice", alicePassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if identity.GetDN() != aliceDN {
		t.Errorf("DN = %q, want %q", identity.GetDN(), aliceDN)
	}
}

func TestReasonNames(t *testing.T) {
	t.Parallel()

	// The names are metrics labels, so they are part of the API in
	// everything but the compiler's opinion.
	cases := map[ldapauth.RejectionReason]string{
		ldapauth.ReasonUnspecified:           "unspecified",
		ldapauth.ReasonBadPassword:           "bad-password",
		ldapauth.ReasonNoSuchUser:            "no-such-user",
		ldapauth.ReasonAccountDisabled:       "account-disabled",
		ldapauth.ReasonAccountLocked:         "account-locked",
		ldapauth.ReasonAccountExpired:        "account-expired",
		ldapauth.ReasonPasswordExpired:       "password-expired",
		ldapauth.ReasonPasswordMustChange:    "password-must-change",
		ldapauth.ReasonTimeRestricted:        "time-restricted",
		ldapauth.ReasonWorkstationRestricted: "workstation-restricted",
		ldapauth.RejectionReason(200):        "RejectionReason(200)",
	}

	for reason, want := range cases {
		if got := reason.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}

func TestReferralPolicyNames(t *testing.T) {
	t.Parallel()

	cases := map[ldapauth.ReferralPolicy]string{
		ldapauth.ReferralIgnore:      "ignore",
		ldapauth.ReferralFail:        "fail",
		ldapauth.ReferralPolicy(200): "ReferralPolicy(200)",
	}

	for policy, want := range cases {
		if got := policy.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}

func TestReloadableDelegatesEverything(t *testing.T) {
	t.Parallel()

	// It implements Authenticator, so every method has to reach the
	// client underneath rather than a zero value.
	dir := newDirectory()

	client := searchAuth(t, dir,
		ldapauth.WithCache(time.Minute),
		ldapauth.WithEmailAttribute("mail"),
	)

	auth := ldapauth.NewReloadable(client)

	ctx := testContext(t)

	if _, err := auth.Authenticate(ctx, "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	identity, err := auth.Lookup(ctx, "alice")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if identity.GetEmail() != "alice@example.com" {
		t.Errorf("Email = %q, want it read through the delegate", identity.GetEmail())
	}

	if err := auth.HealthCheck(ctx); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}

	if stats := auth.Stats(ctx); stats.Servers != 1 {
		t.Errorf("Servers = %d, want 1", stats.Servers)
	}

	dropped, err := auth.InvalidateUser(ctx, "alice")
	if err != nil {
		t.Fatalf("InvalidateUser: %v", err)
	}

	if dropped != 1 {
		t.Errorf("InvalidateUser dropped %d, want 1", dropped)
	}

	if _, err := auth.Authenticate(ctx, "alice", alicePassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if _, err := auth.InvalidateAll(ctx); err != nil {
		t.Fatalf("InvalidateAll: %v", err)
	}

	if err := auth.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := auth.Authenticate(ctx, "alice", alicePassword); !errors.Is(err, ldapauth.ErrClosed) {
		t.Errorf("err = %v, want ErrClosed after Close", err)
	}
}

func TestNewReloadableRefusesNothing(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("NewReloadable accepted a nil client")
		}
	}()

	ldapauth.NewReloadable(nil)
}
