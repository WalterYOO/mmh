package core

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mritd/mmh/common"

	"golang.org/x/crypto/ssh"
)

const (
	// keepAliveRequest is the standard OpenSSH keepalive global request. A
	// server may answer it with failure, which still proves the transport is
	// alive, so only a transport error or a reply timeout is a failure.
	keepAliveRequest = "keepalive@openssh.com"

	// keepAliveMaxTimeouts is how many consecutive reply timeouts fail the
	// tunnel: the first one is tolerated, the second one fails it. A clear
	// transport error fails at once, a timeout may also be caused by a busy
	// server or a jittery link.
	keepAliveMaxTimeouts = 2

	// defaultKeepAliveInterval is used when server_alive_interval is invalid
	defaultKeepAliveInterval = 10 * time.Second
)

// errKeepAliveTimeout is returned when the server does not answer a keepalive
// request in time; the transport may be a black hole.
var errKeepAliveTimeout = errors.New("keepalive reply timeout")

// Tunnel will open an ssh tcp tunnel between the left address and the right address
func Tunnel(name, leftAddr, rightAddr string, reverse bool) error {
	server, err := findServerByName(name)
	if err != nil {
		return err
	}
	interval := normalizeKeepAliveInterval(server.ServerAliveInterval)

	if !reverse {
		listener, err := net.Listen("tcp", leftAddr)
		if err != nil {
			return err
		}
		fmt.Printf("mmh tunnel listen at %s\n", leftAddr)

		client, err := server.wrapperClient(false)
		if err != nil {
			// the local listener has not been handed to forwardTunnel yet
			_ = listener.Close()
			return err
		}
		defer func() { _ = client.Close() }()

		return forwardTunnel(name, listener, client, rightAddr, interval)
	}

	fmt.Printf("mmh reverse tunnel listen at [%s] %s\n", name, rightAddr)
	client, err := server.wrapperClient(false)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	listener, err := client.Listen("tcp", rightAddr)
	if err != nil {
		return err
	}

	return reverseTunnel(name, listener, client, leftAddr, interval)
}

// forwardTunnel serves local connections until the listener is closed. The
// listener and client are passed in so the loop can be tested on its own.
func forwardTunnel(name string, listener net.Listener, client *ssh.Client, rightAddr string, interval time.Duration) error {
	defer func() { _ = listener.Close() }()
	// closing the local listener is the only way to unblock Accept
	ka := startTunnelKeepAlive(client, interval, func() { _ = listener.Close() })
	defer ka.Close()

	for {
		leftConn, err := listener.Accept()
		if err != nil {
			if kaErr := ka.Err(); kaErr != nil {
				return keepAliveError(kaErr)
			}
			// a closed listener keeps returning the same error: continuing
			// would spin and print forever
			if isClosedConnError(err) {
				return err
			}
			common.PrintErr(err)
			continue
		}

		fmt.Printf("new connection %s => [%s] => %s\n", leftConn.LocalAddr(), name, rightAddr)
		rightConn, err := client.Dial("tcp", rightAddr)
		if err != nil {
			// client.Dial 失败时 rightConn 为 nil，已接受的 leftConn 必须关闭，
			// 否则每次失败都会泄漏一个本地 fd，最终导致 accept 报 "too many open files"
			_ = leftConn.Close()
			// when the client was torn down by keepalive, report that cause
			// instead of the dial error it produced
			if kaErr := ka.Err(); kaErr != nil {
				return keepAliveError(kaErr)
			}
			common.PrintErr(err)
			continue
		}

		go connCopy(rightConn, leftConn)
	}
}

// reverseTunnel serves connections forwarded by the ssh server until the
// tunnel is closed. The listener and client are passed in so the loop can be
// tested on its own.
func reverseTunnel(name string, listener net.Listener, client *ssh.Client, leftAddr string, interval time.Duration) error {
	defer func() { _ = listener.Close() }()
	// client.Close() already wakes an ssh listener's Accept; closing it here
	// too is a fallback and is safe because keepalive closes the client first
	ka := startTunnelKeepAlive(client, interval, func() { _ = listener.Close() })
	defer ka.Close()

	for {
		rightConn, err := listener.Accept()
		if err != nil {
			kaErr := ka.Err()
			// the server closing the connection normally makes both Accept and
			// an in-flight keepalive probe fail with io.EOF; it must stay a
			// normal stop, not a keepalive failure
			if err == io.EOF && (kaErr == nil || errors.Is(kaErr, io.EOF)) {
				fmt.Printf("Server [%s] ssh connection is closed, stop ssh tunnel.\n", name)
				return nil
			}
			if kaErr != nil {
				return keepAliveError(kaErr)
			}
			if isClosedConnError(err) {
				return err
			}
			common.PrintErr(err)
			continue
		}

		fmt.Printf("new connection %s:%s => [local] => %s\n", name, rightConn.RemoteAddr(), leftAddr)
		leftConn, err := net.Dial("tcp", leftAddr)
		if err != nil {
			// 本地 dial 失败时 rightConn(远端 ssh channel) 必须关闭，
			// 否则每条失败请求都会在服务端留下一个已接受的连接
			_ = rightConn.Close()
			if kaErr := ka.Err(); kaErr != nil {
				return keepAliveError(kaErr)
			}
			common.PrintErr(err)
			continue
		}
		go connCopy(leftConn, rightConn)
	}
}

// keepAliveError wraps a keepalive failure so the caller and the user see why
// the tunnel stopped
func keepAliveError(err error) error {
	return fmt.Errorf("ssh keepalive failed, stop ssh tunnel: %w", err)
}

// normalizeKeepAliveInterval keeps a misconfigured server_alive_interval from
// flooding the server and matches the interactive shell behavior: anything
// below the default falls back to the default. Tests call the probe runner
// directly, so short intervals are still possible there.
func normalizeKeepAliveInterval(interval time.Duration) time.Duration {
	if interval < defaultKeepAliveInterval {
		return defaultKeepAliveInterval
	}
	return interval
}

// keepAliveProbe sends one keepalive request and waits at most timeout for the
// reply. A failure reply is not an error. The request is sent in a goroutine
// because SendRequest blocks forever when the transport is a black hole; the
// caller closes the client on timeout, which releases that goroutine.
func keepAliveProbe(client *ssh.Client, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest(keepAliveRequest, true, nil)
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("%w within %s", errKeepAliveTimeout, timeout)
	}
}

// tunnelKeepAlive probes the ssh connection periodically. A failed probe means
// the transport is dead: the error is recorded and the client is closed so the
// tunnel's blocking Dial/Accept can return.
type tunnelKeepAlive struct {
	client   *ssh.Client
	interval time.Duration
	unblock  func()

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}

	mu  sync.Mutex
	err error
}

// startTunnelKeepAlive starts a keepalive runner for client; unblock is called
// after a failed probe to wake the tunnel's Accept, it may be nil.
func startTunnelKeepAlive(client *ssh.Client, interval time.Duration, unblock func()) *tunnelKeepAlive {
	if interval <= 0 {
		// Time.NewTicker panics on a non-positive interval; this only guards
		// programmatic callers, configs are normalized before this point
		interval = defaultKeepAliveInterval
	}

	k := &tunnelKeepAlive{
		client:   client,
		interval: interval,
		unblock:  unblock,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go k.run()
	return k
}

func (k *tunnelKeepAlive) run() {
	defer close(k.done)

	ticker := time.NewTicker(k.interval)
	defer ticker.Stop()

	timeouts := 0
	for {
		select {
		case <-k.stop:
			return
		case <-ticker.C:
			err := keepAliveProbe(k.client, k.interval)
			if err == nil {
				timeouts = 0
				continue
			}
			// Close closes the client while a probe may be in flight; that
			// probe then fails with a closed connection error, which must not
			// be recorded as a tunnel failure
			select {
			case <-k.stop:
				return
			default:
			}
			if errors.Is(err, errKeepAliveTimeout) {
				timeouts++
				if timeouts < keepAliveMaxTimeouts {
					continue
				}
			}
			k.fail(err)
			return
		}
	}
}

// fail records the failure before closing the client and unblocking the loop,
// so Err already returns the cause when Accept/Dial wake up
func (k *tunnelKeepAlive) fail(err error) {
	k.mu.Lock()
	if k.err == nil {
		k.err = err
	}
	k.mu.Unlock()

	// close the transport first: an ssh listener's Close sends a request that
	// returns immediately only when the client is already closed
	_ = k.client.Close()
	if k.unblock != nil {
		k.unblock()
	}
}

// Err returns the recorded keepalive failure, or nil if none happened yet; it
// never blocks
func (k *tunnelKeepAlive) Err() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.err
}

// Close stops the probe loop and waits for it to exit. It closes the client
// first so an in-flight probe returns immediately instead of holding Close for
// a whole interval.
func (k *tunnelKeepAlive) Close() {
	k.stopOnce.Do(func() { close(k.stop) })
	_ = k.client.Close()
	<-k.done
}

// closeWrite half-closes the write side of a connection if it supports it,
// so that EOF can be propagated to the peer (ssh.Channel and *net.TCPConn both do).
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func connCopy(rc, lc net.Conn) {
	defer func() {
		_ = rc.Close()
		_ = lc.Close()
	}()

	go func() {
		_, err := io.Copy(rc, lc)
		reportCopyErr(err)
		// local client closed its write side, propagate EOF to the remote target,
		// otherwise the remote keep-alive connection (e.g. http proxy) never closes
		closeWrite(rc)
	}()

	_, err := io.Copy(lc, rc)
	reportCopyErr(err)
	closeWrite(lc)
}

// reportCopyErr reports copy errors, but not the closed connection error which
// is caused by connCopy itself: when one direction finishes, the deferred Close
// interrupts the other direction still blocked in io.Copy, that is the normal
// tunnel teardown and must not be printed as a failure
func reportCopyErr(err error) {
	if err != nil && !isClosedConnError(err) {
		common.PrintErr(err)
	}
}

// isClosedConnError reports whether err was caused by using a connection which
// is already closed
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	// fallback for wrapped errors which do not unwrap to net.ErrClosed
	return strings.Contains(err.Error(), "use of closed network connection")
}
