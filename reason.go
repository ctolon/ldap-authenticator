package ldapauth

import (
	"errors"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// A RejectionReason is why the directory refused a credential, when the
// directory said.
//
// [Client.Authenticate] returns [ErrInvalidCredentials] for every one of
// these, and that is deliberate: a login form that could tell "wrong
// password" from "no such user" is an account enumeration oracle, and one
// that could tell "password expired" from either is a slower one. The
// reason is for the other audience — the operator reading a log, the
// auditor asking why logins from one department all failed last Tuesday —
// and it reaches them through [AuthError.Reason] rather than through
// anything a caller might put in a response body.
//
// Where it comes from:
//
//	Active Directory   the data code in the bind error, always available
//	OpenLDAP and 389   the password policy control, with WithPasswordPolicyControl
//	anything else      ReasonUnspecified
//
// A reason is a hint, not a guarantee. Directories are inconsistent about
// which of these they distinguish, several of them deliberately blur the
// distinction, and a directory that says nothing is not saying the
// password was right.
type RejectionReason uint8

const (
	// ReasonUnspecified is a refusal the directory did not explain.
	ReasonUnspecified RejectionReason = iota

	// ReasonBadPassword is the account existing and the password not
	// matching.
	ReasonBadPassword

	// ReasonNoSuchUser is the account not existing. Note that most
	// directories report it as a bad password on purpose.
	ReasonNoSuchUser

	// ReasonAccountDisabled is an account an administrator has switched
	// off.
	ReasonAccountDisabled

	// ReasonAccountLocked is an account the directory's own lockout
	// policy has locked, usually after failed attempts. See
	// WithLockoutProtection.
	ReasonAccountLocked

	// ReasonAccountExpired is an account past its expiry date.
	ReasonAccountExpired

	// ReasonPasswordExpired is a valid password that is too old to use.
	ReasonPasswordExpired

	// ReasonPasswordMustChange is a password that must be reset before
	// the account can be used, typically after an administrator reset it.
	ReasonPasswordMustChange

	// ReasonTimeRestricted is an account not permitted to log in at this
	// hour.
	ReasonTimeRestricted

	// ReasonWorkstationRestricted is an account not permitted to log in
	// from this machine.
	ReasonWorkstationRestricted
)

// String returns a stable, lower-case name for the reason, suitable for
// a log field or a metrics label. The set is closed, so it is safe as a
// label value.
func (r RejectionReason) String() string {
	switch r {
	case ReasonUnspecified:
		return "unspecified"
	case ReasonBadPassword:
		return "bad-password"
	case ReasonNoSuchUser:
		return "no-such-user"
	case ReasonAccountDisabled:
		return "account-disabled"
	case ReasonAccountLocked:
		return "account-locked"
	case ReasonAccountExpired:
		return "account-expired"
	case ReasonPasswordExpired:
		return "password-expired"
	case ReasonPasswordMustChange:
		return "password-must-change"
	case ReasonTimeRestricted:
		return "time-restricted"
	case ReasonWorkstationRestricted:
		return "workstation-restricted"
	default:
		return "RejectionReason(" + strconv.Itoa(int(r)) + ")"
	}
}

// Actionable reports whether the reason is one the user could do something
// about by trying different credentials.
//
// A bad password is: try again. An expired password, a disabled account,
// or a time restriction is not — the user can type all day and it will
// keep failing. It is the distinction worth surfacing to a help desk, and
// the one worth counting separately in a dashboard, because a rise in
// unactionable refusals is an operational event rather than an attack.
func (r RejectionReason) Actionable() bool {
	switch r {
	case ReasonBadPassword, ReasonNoSuchUser, ReasonUnspecified:
		return true
	default:
		return false
	}
}

// ReasonFor extracts the [RejectionReason] from an error, or
// [ReasonUnspecified] if there is none.
//
//	if ldapauth.ReasonFor(err) == ldapauth.ReasonPasswordExpired {
//	    audit.Record(username, "password expired")
//	}
//
// The response you send the user should not depend on this. What it is
// for is the log line, the audit trail, and the metric label.
func ReasonFor(err error) RejectionReason {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr.Reason
	}

	return ReasonUnspecified
}

// Active Directory reports why a bind failed in the text of an otherwise
// generic "invalid credentials" error, as a hexadecimal code after the
// word "data":
//
//	80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext
//	error, data 52e, v3839
//
// The codes are stable and documented, and they are the only way to tell
// an expired password from a wrong one on AD.
const (
	adNoSuchUser            = "525"
	adBadPassword           = "52e"
	adTimeRestricted        = "530"
	adWorkstationRestricted = "531"
	adPasswordExpired       = "532"
	adAccountDisabled       = "533"
	adAccountExpired        = "701"
	adPasswordMustChange    = "773"
	adAccountLocked         = "775"
)

// reasonFromError reads Active Directory's data code out of a bind error.
func reasonFromError(err error) RejectionReason {
	if err == nil {
		return ReasonUnspecified
	}

	code := adDataCode(err.Error())
	if code == "" {
		return ReasonUnspecified
	}

	switch code {
	case adNoSuchUser:
		return ReasonNoSuchUser
	case adBadPassword:
		return ReasonBadPassword
	case adTimeRestricted:
		return ReasonTimeRestricted
	case adWorkstationRestricted:
		return ReasonWorkstationRestricted
	case adPasswordExpired:
		return ReasonPasswordExpired
	case adAccountDisabled:
		return ReasonAccountDisabled
	case adAccountExpired:
		return ReasonAccountExpired
	case adPasswordMustChange:
		return ReasonPasswordMustChange
	case adAccountLocked:
		return ReasonAccountLocked
	default:
		return ReasonUnspecified
	}
}

// adDataCode pulls the hexadecimal code out of ", data 52e," and its
// variants. It is deliberately forgiving about the punctuation around it,
// because the surrounding text is a human-readable string that has changed
// between Windows versions and will again.
func adDataCode(message string) string {
	const marker = "data "

	index := strings.Index(message, marker)
	if index < 0 {
		return ""
	}

	rest := message[index+len(marker):]

	end := 0
	for end < len(rest) && isHexDigit(rest[end]) {
		end++
	}

	// A code is three or four hex digits. Anything else is the word
	// "data" appearing in a sentence.
	if end < 3 || end > 4 {
		return ""
	}

	return strings.ToLower(rest[:end])
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// The password policy control's error codes, from
// draft-behera-ldap-password-policy. go-ldap parses the control but does
// not name the codes.
const (
	beheraPasswordExpired   int8 = 0
	beheraAccountLocked     int8 = 1
	beheraChangeAfterReset  int8 = 2
	beheraPasswordTooShort  int8 = 6
	beheraPasswordTooYoung  int8 = 7
	beheraPasswordInHistory int8 = 8
)

// reasonFromControls reads the password policy control that OpenLDAP, 389
// Directory Server and their relatives return when it is asked for.
func reasonFromControls(controls []ldap.Control) RejectionReason {
	found := ldap.FindControl(controls, ldap.ControlTypeBeheraPasswordPolicy)

	policy, ok := found.(*ldap.ControlBeheraPasswordPolicy)
	if !ok || policy == nil {
		return ReasonUnspecified
	}

	switch policy.Error {
	case beheraPasswordExpired:
		return ReasonPasswordExpired
	case beheraAccountLocked:
		return ReasonAccountLocked
	case beheraChangeAfterReset:
		return ReasonPasswordMustChange
	case beheraPasswordTooShort, beheraPasswordTooYoung, beheraPasswordInHistory:
		// These are answers to a password *change*, not to a bind. They
		// should not reach here, and if they do they say nothing about
		// why the credential was refused.
		return ReasonUnspecified
	default:
		return ReasonUnspecified
	}
}
