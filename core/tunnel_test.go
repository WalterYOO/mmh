package core

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
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
