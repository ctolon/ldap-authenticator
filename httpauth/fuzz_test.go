package httpauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctolon/ldap-authenticator/httpauth"
)

// Credentials reads whatever arrives on the wire, which means it reads
// whatever anybody cares to send. These targets assert the two properties
// that matter: it never panics, and it never invents a credential out of a
// request that did not carry one.

func FuzzCredentials(f *testing.F) {
	seeds := []struct{ contentType, body, authorization string }{
		{"application/json", `{"username":"alice","password":"s3cret"}`, ""},
		{"application/json", `{"username":"alice"}`, ""},
		{"application/json", `{`, ""},
		{"application/json", ``, ""},
		{"application/json", `{"username":123,"password":null}`, ""},
		{"application/json", strings.Repeat(`{"a":`, 512), ""},
		{"application/x-www-form-urlencoded", "username=alice&password=s3cret", ""},
		{"application/x-www-form-urlencoded", "%%%%", ""},
		{"application/x-www-form-urlencoded", strings.Repeat("a=b&", 4096), ""},
		{"text/plain", "alice:s3cret", ""},
		{"", "", "Basic YWxpY2U6czNjcmV0"},
		{"", "", "Basic"},
		{"", "", "Basic !!!"},
		{"", "", "Bearer abc"},
		{"", "", strings.Repeat("Basic ", 100)},
		{"application/json; charset=utf-8", `{"username":"a","password":"b"}`, ""},
	}

	for _, seed := range seeds {
		f.Add(seed.contentType, seed.body, seed.authorization)
	}

	f.Fuzz(func(t *testing.T, contentType, body, authorization string) {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))

		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}

		username, password, err := httpauth.Credentials(req, httpauth.DefaultMaxBodyBytes)

		if err != nil {
			// A failure must not smuggle a credential out alongside it.
			if username != "" || password != "" {
				t.Fatalf("error %v came with username %q and password %q", err, username, password)
			}

			return
		}

		// Every character in a credential has to have come from at least
		// one byte of the request. That is the honest form of "the
		// parser did not invent this": counting bytes is wrong, because
		// a decoder can legitimately produce more bytes than it consumed
		// — JSON replaces each invalid UTF-8 byte with U+FFFD, which is
		// three — but no decoder here produces more *characters* than it
		// was given bytes.
		characters := len([]rune(username)) + len([]rune(password))

		if characters > len(body)+len(authorization) {
			t.Fatalf("credentials are %d characters from a %d byte request: username %q password %q",
				characters, len(body)+len(authorization), username, password)
		}

		// Parsing the same request twice must give the same answer. A
		// parser that depended on anything but its input would be a
		// parser whose result depends on what happened before it.
		again := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))

		if contentType != "" {
			again.Header.Set("Content-Type", contentType)
		}

		if authorization != "" {
			again.Header.Set("Authorization", authorization)
		}

		secondUsername, secondPassword, secondErr := httpauth.Credentials(again, httpauth.DefaultMaxBodyBytes)

		if secondUsername != username || secondPassword != password || (secondErr == nil) != (err == nil) {
			t.Fatalf("parsing the same request twice gave %q/%q/%v then %q/%q/%v",
				username, password, err, secondUsername, secondPassword, secondErr)
		}
	})
}

// FuzzCredentialsRefusesAnEmptyRequest is the other half: whatever the
// content type says, a request carrying nothing must produce no
// credentials at all.
func FuzzCredentialsRefusesAnEmptyRequest(f *testing.F) {
	for _, seed := range []string{"", "application/json", "application/x-www-form-urlencoded", "text/plain", ";", "  "} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, contentType string) {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(""))

		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		username, password, err := httpauth.Credentials(req, httpauth.DefaultMaxBodyBytes)

		if err == nil && (username != "" || password != "") {
			t.Fatalf("an empty request produced username %q and password %q", username, password)
		}
	})
}

func FuzzStatusIsAlwaysAValidCode(f *testing.F) {
	// Status is the mapping every adapter uses to decide what to send.
	// A code outside the HTTP range would be a panic in net/http rather
	// than a wrong answer.
	f.Add(0)
	f.Add(1)
	f.Add(-1)

	f.Fuzz(func(t *testing.T, kind int) {
		errs := []error{
			nil,
			httpauth.ErrForbidden,
			httpauth.ErrNoCredentials,
			httpauth.ErrMalformedRequest,
			errors.New("something nobody planned for"),
		}

		err := errs[((kind%len(errs))+len(errs))%len(errs)]

		if status := httpauth.Status(err); status < 100 || status > 599 {
			t.Fatalf("Status(%v) = %d, which is not an HTTP status code", err, status)
		}
	})
}
