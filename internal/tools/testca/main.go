// Command testca writes a throwaway CA and server certificate for the
// integration directory.
//
//	go run ./internal/tools/testca -dir integration/testdata -host ldap.example.org
//
// The container image ships its own self-signed CA, and that CA expired in
// January 2026. Verification then fails for a reason that has nothing to
// do with this library, and the tempting fix — InsecureSkipVerify — would
// turn the TLS tests into tests that pass against any certificate at all,
// including one an attacker presented. So the certificates are generated
// here, where their validity is under our control.
//
// Nothing produced here is a secret. The key never leaves the test
// container, the certificate is valid for a hostname that does not exist,
// and both are regenerated whenever the volume is.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	var (
		dir   = flag.String("dir", "integration/testdata", "where to write the certificates")
		host  = flag.String("host", "ldap.example.org", "the name the server certificate is issued for")
		valid = flag.Duration("valid", 365*24*time.Hour, "how long the certificates are valid for")
		renew = flag.Duration("renew-before", 30*24*time.Hour, "regenerate when less than this is left")
		force = flag.Bool("force", false, "regenerate even when the existing certificates are fine")
	)

	flag.Parse()

	if !*force && usable(*dir, *host, *renew) {
		fmt.Printf("keeping the existing certificates for %s\n", *host)

		return
	}

	if err := generate(*dir, *host, *valid); err != nil {
		fmt.Fprintln(os.Stderr, "testca:", err)
		os.Exit(1)
	}
}

// usable reports whether the certificates already on disk can be left
// alone.
//
// This is not an optimisation. Regenerating them while a container is
// already running replaces the CA the client will verify against while the
// server carries on presenting a certificate signed by the old one, and
// the handshake then fails with a signature error that looks like a bug in
// the library rather than a stale container.
func usable(dir, host string, renewBefore time.Duration) bool {
	for _, name := range []string{"ca.crt", "ldap.crt", "ldap.key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return false
		}
	}

	pemBytes, err := os.ReadFile(filepath.Join(dir, "ldap.crt"))
	if err != nil {
		return false
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	if cert.VerifyHostname(host) != nil {
		return false
	}

	return time.Until(cert.NotAfter) > renewBefore
}

func generate(dir, host string, valid time.Duration) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	// Backdated by an hour, so that a clock skew of a few seconds between
	// the host and the container is not a test failure.
	notBefore := time.Now().Add(-time.Hour)
	notAfter := notBefore.Add(valid)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating the CA key: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{Organization: []string{"ldap-authenticator integration"}, CommonName: "integration CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("signing the CA: %w", err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return fmt.Errorf("parsing the CA: %w", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating the server key: %w", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{Organization: []string{"ldap-authenticator integration"}, CommonName: host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("signing the server certificate: %w", err)
	}

	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("marshalling the server key: %w", err)
	}

	files := []struct {
		name  string
		block *pem.Block
		mode  os.FileMode
	}{
		{"ca.crt", &pem.Block{Type: "CERTIFICATE", Bytes: caDER}, 0o644},
		{"ldap.crt", &pem.Block{Type: "CERTIFICATE", Bytes: serverDER}, 0o644},
		{"ldap.key", &pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}, 0o644},
	}

	for _, file := range files {
		path := filepath.Join(dir, file.name)

		// The container reads these as a non-root user, which is why the
		// key is not 0600. It is a throwaway key for a hostname that does
		// not exist; there is nothing here to protect.
		if err := os.WriteFile(path, pem.EncodeToMemory(file.block), file.mode); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}

	fmt.Printf("wrote a CA and a certificate for %s, valid until %s\n", host, notAfter.Format(time.DateOnly))

	return nil
}

func serial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)

	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(err)
	}

	return n
}
