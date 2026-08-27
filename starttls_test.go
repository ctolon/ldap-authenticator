package ldapauth_test

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	ldapauth "github.com/ctolon/ldap-authenticator"
)

// silentServer accepts TCP connections and then does nothing with them:
// no LDAP response, no close. It is the shape of a directory that is up
// enough to accept a connection and wedged enough to answer nothing, and
// it is also what a deliberately hostile server would do.
type silentServer struct {
	listener net.Listener

	// reply is written to each connection before going silent. Empty
	// means answer nothing at all.
	reply []byte

	mu       sync.Mutex
	accepted []net.Conn
	closed   bool
}

func newSilentServer(t *testing.T, reply []byte) *silentServer {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &silentServer{listener: listener, reply: reply}

	go s.serve()

	t.Cleanup(s.stop)

	return s
}

func (s *silentServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		s.mu.Lock()

		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()

			return
		}

		s.accepted = append(s.accepted, conn)
		s.mu.Unlock()

		if len(s.reply) > 0 {
			// Answer the StartTLS request, then never begin the TLS
			// handshake. go-ldap runs that handshake with no deadline on
			// the socket, so this is the hang that no timeout in the
			// configuration reaches.
			go func(conn net.Conn) {
				buffer := make([]byte, 512)

				if _, err := conn.Read(buffer); err != nil {
					return
				}

				_, _ = conn.Write(s.reply)
			}(conn)
		}
	}
}

func (s *silentServer) url() string {
	return "ldap://" + s.listener.Addr().String()
}

// waitForConnection blocks until the server has accepted one, so that a
// test asserting on a hang is not really asserting on a slow dial.
func (s *silentServer) waitForConnection(t *testing.T) net.Conn {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		s.mu.Lock()
		accepted := len(s.accepted)

		var first net.Conn
		if accepted > 0 {
			first = s.accepted[0]
		}

		s.mu.Unlock()

		if accepted > 0 {
			return first
		}

		time.Sleep(time.Millisecond)
	}

	t.Fatal("the server accepted no connection")

	return nil
}

func (s *silentServer) stop() {
	s.mu.Lock()
	s.closed = true
	accepted := append([]net.Conn(nil), s.accepted...)
	s.mu.Unlock()

	_ = s.listener.Close()

	for _, conn := range accepted {
		_ = conn.Close()
	}
}

// startTLSSuccess is an LDAP ExtendedResponse carrying resultCode 0, hand
// encoded because the BER library is go-ldap's dependency and not this
// package's:
//
//	30 0c                SEQUENCE, 12 bytes
//	   02 01 01          INTEGER  messageID = 1
//	   78 07             [APPLICATION 24] ExtendedResponse, 7 bytes
//	      0a 01 00       ENUMERATED resultCode = success
//	      04 00          OCTET STRING matchedDN = ""
//	      04 00          OCTET STRING diagnosticMessage = ""
var startTLSSuccess = []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}

func TestStartTLSHonoursTheCallersDeadlineWhenTheServerNeverAnswers(t *testing.T) {
	t.Parallel()

	// The TCP connection is established, so net.Dialer's timeout has
	// already been satisfied and has nothing further to say. What bounds
	// the wait for the StartTLS response is the deadline this package
	// puts on the connection before sending it.
	server := newSilentServer(t, nil)

	auth := startTLSAuth(t, server.url())

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	started := time.Now()

	_, err := auth.Authenticate(ctx, "alice", "s3cret")

	assertBounded(t, started, err)
}

func TestStartTLSHonoursTheCallersDeadlineWhenTheHandshakeNeverBegins(t *testing.T) {
	t.Parallel()

	// The harder half. The server answers StartTLS and then sends nothing
	// more, so go-ldap enters a TLS handshake on a socket with no
	// deadline on it. Nothing but closing the connection ends that, which
	// is why cancellation has to hold the connection rather than race a
	// goroutine for it.
	server := newSilentServer(t, startTLSSuccess)

	auth := startTLSAuth(t, server.url())

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	started := time.Now()

	_, err := auth.Authenticate(ctx, "alice", "s3cret")

	assertBounded(t, started, err)
}

func TestAWedgedStartTLSDoesNotLeaveTheSocketOpen(t *testing.T) {
	t.Parallel()

	// This is the one that fails without the phase split. Abandoning the
	// dial goroutine returned to the caller on time but left it blocked
	// in a TLS handshake that go-ldap runs with no deadline on the
	// socket — so the connection stayed open on both sides until
	// something else closed it, and a server that accepts connections and
	// stops talking cost a file descriptor per attempt.
	server := newSilentServer(t, startTLSSuccess)

	auth := startTLSAuth(t, server.url())

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if _, err := auth.Authenticate(ctx, "alice", "s3cret"); err == nil {
		t.Fatal("Authenticate succeeded against a server that never handshakes")
	}

	conn := server.waitForConnection(t)

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	// Draining rather than reading once: the client got far enough to
	// send a TLS ClientHello, and those bytes are sitting in the server's
	// receive buffer whether or not the socket is still open. What proves
	// the close is the read that comes back with an error rather than
	// blocking until the deadline.
	buffer := make([]byte, 4096)

	for {
		_, err := conn.Read(buffer)
		if err == nil {
			continue
		}

		if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("the server's connection stayed open for five seconds after the client gave up")
		}

		return
	}
}

func TestAWedgedStartTLSDoesNotLeakAGoroutine(t *testing.T) {
	// Not parallel: it counts goroutines, and another test starting one
	// alongside would be indistinguishable from a leak.
	server := newSilentServer(t, startTLSSuccess)

	auth := startTLSAuth(t, server.url())

	settle(t)

	before := runtime.NumGoroutine()

	const attempts = 20

	for range attempts {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)

		if _, err := auth.Authenticate(ctx, "alice", "s3cret"); err == nil {
			cancel()
			t.Fatal("Authenticate succeeded against a server that never handshakes")
		}

		cancel()
	}

	settle(t)

	// Each abandoned handshake used to hold a goroutine indefinitely, so
	// twenty attempts left twenty behind — and a server doing this on
	// purpose could leave as many as it liked. The slack is for the
	// runtime's own churn, not for a linear leak.
	if leaked := runtime.NumGoroutine() - before; leaked > attempts/2 {
		t.Errorf("%d goroutines outlived %d wedged handshakes", leaked, attempts)
	}
}

// settle waits for goroutine count to stop moving, so that a count taken
// straight after I/O is not really a count of teardown in progress.
func settle(t *testing.T) {
	t.Helper()

	previous := -1

	for range 100 {
		time.Sleep(20 * time.Millisecond)

		current := runtime.NumGoroutine()
		if current == previous {
			return
		}

		previous = current
	}
}

func startTLSAuth(t *testing.T, url string) *ldapauth.Client {
	t.Helper()

	auth, err := ldapauth.New(
		ldapauth.WithURL(url),
		ldapauth.WithStartTLS(),
		ldapauth.WithInsecureSkipVerify(),
		ldapauth.WithDirectBind("uid={{username}},ou=people,dc=corp,dc=example"),
		ldapauth.WithRetry(0),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Cleanup(func() { _ = auth.Close() })

	return auth
}

// assertBounded fails unless the call came back near its deadline with an
// error.
//
// This is the weaker of the two properties, and it held before the dial
// was split into phases as well: racing the whole goroutine returned to
// the caller on time. What it did not do was end the goroutine or close
// the socket, which is what TestAWedgedStartTLSDoesNotLeaveTheSocketOpen
// and TestAWedgedStartTLSDoesNotLeakAGoroutine are for. It is kept because
// it is the property a caller actually depends on, and a future change to
// the phase split could lose it without touching either of those.
func assertBounded(t *testing.T, started time.Time, err error) {
	t.Helper()

	elapsed := time.Since(started)

	if err == nil {
		t.Fatalf("Authenticate succeeded against a silent server after %s", elapsed)
	}

	if elapsed > 5*time.Second {
		t.Fatalf("Authenticate took %s to honour a 300ms deadline: %v", elapsed, err)
	}
}
