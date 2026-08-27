module github.com/ctolon/ldap-authenticator/contrib/fiber

go 1.25.0

require (
	github.com/ctolon/ldap-authenticator v1.0.0
	github.com/gofiber/fiber/v2 v2.52.15
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/go-ldap/ldap/v3 v3.4.14 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.18.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.70.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// The root module is required at the version this module is released
// alongside, and replaced with the checkout while working in this
// repository — the tag does not exist until the release that creates it.
//
// A replace directive in a dependency's go.mod is ignored by whoever
// imports it, so this affects builds inside this repository and nothing
// else. CI drops it and builds against the published version once a
// release exists; see RELEASING.md.
replace github.com/ctolon/ldap-authenticator => ../..
