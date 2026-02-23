// Package tunnel implements a Cloudflare Tunnel-like feature for Nebula.
//
// It provides two complementary modes:
//
//   - Expose: listen on a Nebula overlay port and proxy incoming connections from
//     Nebula peers to a local TCP service. No inbound firewall ports are required
//     on the host — only the existing Nebula UDP port needs to be reachable.
//
//   - Access: listen on a local TCP port and proxy connections through the Nebula
//     overlay to a remote peer's exposed service.
//
// Both modes use the service.Service layer (backed by a gvisor userspace network
// stack) so no TUN device or root privileges are needed.
package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/service"
)

// Manager manages expose and access tunnel endpoints.
type Manager struct {
	svc *service.Service
	l   *logrus.Logger
}

// New creates a new Manager backed by svc.
func New(svc *service.Service, l *logrus.Logger) *Manager {
	return &Manager{svc: svc, l: l}
}

// StartExpose starts an expose endpoint for rule. It listens on the Nebula
// overlay port specified in rule.ListenPort and proxies each accepted TCP
// connection to rule.Forward. Returns after the listener is registered;
// the accept loop runs in a background goroutine that exits when ctx is done.
func (m *Manager) StartExpose(ctx context.Context, rule ExposeRule) error {
	addr := fmt.Sprintf(":%d", rule.ListenPort)
	ln, err := m.svc.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("expose %q: listen on nebula port %d: %w", rule.Name, rule.ListenPort, err)
	}

	m.l.WithFields(logrus.Fields{
		"name":        rule.Name,
		"nebula_port": rule.ListenPort,
		"forward":     rule.Forward,
	}).Info("[tunnel] Exposing local service to Nebula overlay")

	go m.exposeLoop(ctx, rule, ln)
	return nil
}

func (m *Manager) exposeLoop(ctx context.Context, rule ExposeRule, ln net.Listener) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return // normal shutdown
			}
			m.l.WithError(err).WithField("name", rule.Name).Error("[tunnel] Expose accept error")
			return
		}
		go m.handleExpose(ctx, rule, conn)
	}
}

func (m *Manager) handleExpose(ctx context.Context, rule ExposeRule, nebulaConn net.Conn) {
	defer nebulaConn.Close()

	local, err := (&net.Dialer{}).DialContext(ctx, "tcp", rule.Forward)
	if err != nil {
		m.l.WithError(err).WithFields(logrus.Fields{
			"name":    rule.Name,
			"forward": rule.Forward,
		}).Warn("[tunnel] Failed to connect to local service")
		return
	}
	defer local.Close()

	m.l.WithFields(logrus.Fields{
		"name":    rule.Name,
		"from":    nebulaConn.RemoteAddr(),
		"forward": rule.Forward,
	}).Debug("[tunnel] Proxying Nebula connection to local service")

	proxy(nebulaConn, local)
}

// StartAccess starts an access endpoint for rule. It listens on
// 127.0.0.1:rule.LocalPort and proxies each accepted TCP connection through the
// Nebula overlay to rule.Remote. Returns after the listener is registered; the
// accept loop runs in a background goroutine that exits when ctx is done.
func (m *Manager) StartAccess(ctx context.Context, rule AccessRule) error {
	addr := fmt.Sprintf("127.0.0.1:%d", rule.LocalPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("access %q: listen locally on %s: %w", rule.Name, addr, err)
	}

	m.l.WithFields(logrus.Fields{
		"name":       rule.Name,
		"local_port": rule.LocalPort,
		"remote":     rule.Remote,
	}).Info("[tunnel] Local port access to remote Nebula service")

	go m.accessLoop(ctx, rule, ln)
	return nil
}

func (m *Manager) accessLoop(ctx context.Context, rule AccessRule, ln net.Listener) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return // normal shutdown
			}
			m.l.WithError(err).WithField("name", rule.Name).Error("[tunnel] Access accept error")
			return
		}
		go m.handleAccess(ctx, rule, conn)
	}
}

func (m *Manager) handleAccess(ctx context.Context, rule AccessRule, localConn net.Conn) {
	defer localConn.Close()

	nebulaConn, err := m.svc.DialContext(ctx, "tcp", rule.Remote)
	if err != nil {
		m.l.WithError(err).WithFields(logrus.Fields{
			"name":   rule.Name,
			"remote": rule.Remote,
		}).Warn("[tunnel] Failed to connect to remote Nebula service")
		return
	}
	defer nebulaConn.Close()

	m.l.WithFields(logrus.Fields{
		"name":   rule.Name,
		"from":   localConn.RemoteAddr(),
		"remote": rule.Remote,
	}).Debug("[tunnel] Proxying local connection through Nebula overlay")

	proxy(localConn, nebulaConn)
}

// halfCloser is implemented by both *net.TCPConn and gvisor's *gonet.TCPConn.
// It allows signalling EOF to one direction of a TCP connection without closing
// the other, enabling correct half-close semantics.
type halfCloser interface {
	CloseWrite() error
}

// proxy bidirectionally copies data between a and b. It signals a half-close
// to each side after the other direction's copy finishes, then waits for both
// goroutines before returning.
func proxy(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyHalf := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src) //nolint:errcheck
		// Signal EOF to dst so it knows src is done writing.
		if hc, ok := dst.(halfCloser); ok {
			hc.CloseWrite() //nolint:errcheck
		} else {
			dst.Close()
		}
	}

	go copyHalf(b, a)
	go copyHalf(a, b)
	wg.Wait()
}
