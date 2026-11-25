package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestIsClosedConnError(t *testing.T) {
	if isClosedConnError(nil) {
		t.Error("nil error should not be a closed connection error")
	}
	if isClosedConnError(io.EOF) {
		t.Error("io.EOF should not be a closed connection error")
	}
	if !isClosedConnError(fmt.Errorf("wrapped: %w", net.ErrClosed)) {
		t.Error("wrapped net.ErrClosed should be a closed connection error")
	}

	// a real error produced by using a closed connection
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	_ = conn.Close()
	if _, err = conn.Write([]byte("x")); err == nil {
		t.Fatal("expected an error when writing to a closed connection")
	} else if !isClosedConnError(err) {
		t.Errorf("isClosedConnError(%v) = false, want true", err)
	}
}

// newTCPConnPair returns a connected pair of tcp connections
func newTCPConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	return dialed, <-accepted
}

// TestConnCopyTearsDownOnRemoteEOF makes sure that when the remote side closes,
// connCopy finishes and the local client receives EOF instead of hanging
func TestConnCopyTearsDownOnRemoteEOF(t *testing.T) {
	// localClient is the application using the tunnel, localConn is the
	// connection accepted by the tunnel listener
	localClient, localConn := newTCPConnPair(t)
	// remoteConn is the connection dialed by the tunnel, remotePeer simulates
	// the target service
	remoteConn, remotePeer := newTCPConnPair(t)

	done := make(chan struct{})
	go func() {
		connCopy(remoteConn, localConn)
		close(done)
	}()

	if _, err := remotePeer.Write([]byte("hello")); err != nil {
		t.Fatalf("remote write failed: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(localClient, buf); err != nil {
		t.Fatalf("local read failed: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("unexpected data: %q", buf)
	}

	_ = remotePeer.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("connCopy did not finish after the remote side closed")
	}

	_ = localClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := localClient.Read(buf); err == nil {
		t.Fatal("expected the local client to see EOF after the tunnel closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("local client did not receive EOF")
	}

	_ = localClient.Close()
	_ = localConn.Close()
	_ = remoteConn.Close()
}

func TestNormalizeKeepAliveInterval(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want time.Duration
	}{
		{0, 10 * time.Second},
		{time.Second, 10 * time.Second},
		{10 * time.Second, 10 * time.Second},
		{30 * time.Second, 30 * time.Second},
	}
	for _, c := range cases {
		if got := normalizeKeepAliveInterval(c.in); got != c.want {
			t.Errorf("normalizeKeepAliveInterval(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

// keepAliveTestServer is a minimal ssh server whose global requests are read
// but never answered, so a keepalive probe must time out. With closeOnReq the
// server closes the connection as soon as the first global request arrives,
// which makes a server exit race an in-flight probe deterministically.
type keepAliveTestServer struct {
	addr       string
	firstReq   chan struct{}
	closeOnReq bool
}

func startKeepAliveTestServer(t *testing.T, closeOnReq bool) *keepAliveTestServer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key failed: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("create host signer failed: %v", err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "mmh" && string(pass) == "secret" {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ssh server failed: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	s := &keepAliveTestServer{
		addr:       ln.Addr().String(),
		firstReq:   make(chan struct{}),
		closeOnReq: closeOnReq,
	}
	var firstOnce sync.Once

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				for range reqs {
					firstOnce.Do(func() { close(s.firstReq) })
					if closeOnReq {
						return
					}
					// deliberately never reply: the client must time out
				}
			}(conn)
		}
	}()

	return s
}

// newTunnelTestClient connects a standard ssh client to a test server
func newTunnelTestClient(t *testing.T, addr string) *ssh.Client {
	t.Helper()

	host, port := parseAddr(t, addr)
	client, err := (&Server{Address: host, Port: port, User: "mmh", Password: "secret"}).ssh(false, 0)
	if err != nil {
		t.Fatalf("ssh connect failed: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// eofListener mimics an ssh listener whose connection is gone: Accept returns
// io.EOF as soon as the listener is closed
type eofListener struct {
	addr   net.Addr
	closed chan struct{}
	once   sync.Once
}

func newEOFListener() *eofListener {
	return &eofListener{
		addr:   &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		closed: make(chan struct{}),
	}
}

func (l *eofListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, io.EOF
}

func (l *eofListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *eofListener) Addr() net.Addr { return l.addr }

func TestKeepAliveProbeAlive(t *testing.T) {
	// startSSHServer answers global requests with failure, which still proves
	// the server is alive
	client := newTunnelTestClient(t, startSSHServer(t, "mmh", "secret"))

	if err := keepAliveProbe(client, time.Second); err != nil {
		t.Fatalf("probe on a live server failed: %v", err)
	}
}

func TestKeepAliveProbeTimeout(t *testing.T) {
	srv := startKeepAliveTestServer(t, false)
	client := newTunnelTestClient(t, srv.addr)

	err := keepAliveProbe(client, 100*time.Millisecond)
	if !errors.Is(err, errKeepAliveTimeout) {
		t.Fatalf("expected a timeout error, got %v", err)
	}
	// release the goroutine blocked in SendRequest
	_ = client.Close()
}

func TestKeepAliveProbeClosedClient(t *testing.T) {
	srv := startKeepAliveTestServer(t, false)
	client := newTunnelTestClient(t, srv.addr)
	_ = client.Close()

	if err := keepAliveProbe(client, time.Second); err == nil {
		t.Fatal("expected an error when probing a closed client")
	}
}

func TestForwardTunnelStopsOnKeepAliveFailure(t *testing.T) {
	srv := startKeepAliveTestServer(t, false)
	client := newTunnelTestClient(t, srv.addr)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- forwardTunnel("test", ln, client, "127.0.0.1:1", 50*time.Millisecond)
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "keepalive") {
			t.Fatalf("expected a keepalive failure, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forwardTunnel did not stop after a keepalive failure")
	}

	// the tunnel must close the local listener on the way out
	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
	if _, err := ln.Accept(); err == nil || !isClosedConnError(err) {
		t.Fatalf("listener was not closed, accept returned: %v", err)
	}
}

func TestReverseTunnelStopsOnKeepAliveFailure(t *testing.T) {
	srv := startKeepAliveTestServer(t, false)
	client := newTunnelTestClient(t, srv.addr)
	ln := newEOFListener()

	done := make(chan error, 1)
	go func() {
		done <- reverseTunnel("test", ln, client, "127.0.0.1:1", 50*time.Millisecond)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a keepalive failure, got nil")
		}
		if errors.Is(err, io.EOF) || !strings.Contains(err.Error(), "keepalive") {
			t.Fatalf("expected a keepalive failure, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reverseTunnel did not stop after a keepalive failure")
	}
}

func TestReverseTunnelNormalStopOnEOF(t *testing.T) {
	client := newTunnelTestClient(t, startSSHServer(t, "mmh", "secret"))
	ln := newEOFListener()

	done := make(chan error, 1)
	go func() {
		// a long interval guarantees the keepalive cannot fail in this test
		done <- reverseTunnel("test", ln, client, "127.0.0.1:1", 10*time.Second)
	}()

	_ = ln.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected a normal stop, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reverseTunnel did not stop when the listener reported EOF")
	}
}

func TestReverseTunnelServerEOFWithKeepAliveInFlight(t *testing.T) {
	// the server closes the connection when the first keepalive arrives, so
	// both Accept and the in-flight probe see io.EOF
	srv := startKeepAliveTestServer(t, true)
	client := newTunnelTestClient(t, srv.addr)
	ln := newEOFListener()

	done := make(chan error, 1)
	go func() {
		done <- reverseTunnel("test", ln, client, "127.0.0.1:1", 50*time.Millisecond)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a server-side EOF must stop normally, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reverseTunnel did not stop after the server closed the connection")
	}
}

func TestKeepAliveCloseKeepsErrNil(t *testing.T) {
	srv := startKeepAliveTestServer(t, false)
	client := newTunnelTestClient(t, srv.addr)
	ln := newEOFListener()
	ka := startTunnelKeepAlive(client, 50*time.Millisecond, func() { _ = ln.Close() })

	// wait until a probe is really in flight before closing
	select {
	case <-srv.firstReq:
	case <-time.After(3 * time.Second):
		t.Fatal("keepalive probe was not sent")
	}

	start := time.Now()
	ka.Close()
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Close waited for the in-flight probe: %s", elapsed)
	}
	if err := ka.Err(); err != nil {
		t.Fatalf("Close recorded a keepalive error: %v", err)
	}
}
