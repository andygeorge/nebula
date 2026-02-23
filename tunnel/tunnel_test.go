package tunnel_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"dario.cat/mergo"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/service"
	"github.com/slackhq/nebula/tunnel"
	"go.yaml.in/yaml/v3"
)

type m = map[string]any

// newTestService creates a Nebula service node from a minimal config merged
// with overrides. Panics on any error (test helper).
func newTestService(t *testing.T, caCrt cert.Certificate, caKey []byte, vpnIP netip.Addr, overrides m) *service.Service {
	t.Helper()

	_, _, myPrivKey, myPEM := cert_test.NewTestCert(
		cert.Version2, cert.Curve_CURVE25519, caCrt, caKey,
		vpnIP.String(), time.Now(), time.Now().Add(5*time.Minute),
		[]netip.Prefix{netip.PrefixFrom(vpnIP, 24)}, nil, []string{},
	)
	caB, err := caCrt.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}

	base := m{
		"pki": m{
			"ca":   string(caB),
			"cert": string(myPEM),
			"key":  string(myPrivKey),
		},
		"firewall": m{
			"outbound": []m{{"proto": "any", "port": "any", "host": "any"}},
			"inbound":  []m{{"proto": "any", "port": "any", "host": "any"}},
		},
		"timers": m{
			"pending_deletion_interval": 2,
			"connection_alive_interval": 2,
		},
		"handshakes": m{
			"try_interval": "200ms",
		},
	}
	if overrides != nil {
		if err := mergo.Merge(&overrides, base, mergo.WithAppendSlice); err != nil {
			t.Fatal(err)
		}
		base = overrides
	}

	cb, err := yaml.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}

	var c config.C
	if err := c.LoadString(string(cb)); err != nil {
		t.Fatal(err)
	}

	logger := logrus.New()
	logger.Out = os.Stdout
	logger.SetLevel(logrus.DebugLevel)

	ctrl, err := nebula.Main(&c, false, "test", logger, overlay.NewUserDeviceFromConfig)
	if err != nil {
		t.Fatal(err)
	}

	svc, err := service.New(ctrl)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	return svc
}

// echoServer starts a TCP echo server on a random local port, writes one
// greeting line, then echoes everything it receives back. Returns the listen
// address and a cancel function.
func echoServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte("hello\n")) //nolint:errcheck
				io.Copy(c, c)             //nolint:errcheck
			}(conn)
		}
	}()

	return ln.Addr().String()
}

// TestExpose verifies that StartExpose makes a local service reachable from
// another Nebula node by connecting to the server's Nebula IP:port.
func TestExpose(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519,
		time.Now(), time.Now().Add(10*time.Minute),
		nil, nil, []string{},
	)

	// "server" node acts as lighthouse.
	serverSvc := newTestService(t, ca, caKey, netip.MustParseAddr("10.1.0.1"), m{
		"static_host_map": m{},
		"lighthouse":      m{"am_lighthouse": true},
		"listen":          m{"host": "0.0.0.0", "port": 14243},
	})

	// "client" node connects via the lighthouse.
	clientSvc := newTestService(t, ca, caKey, netip.MustParseAddr("10.1.0.2"), m{
		"static_host_map": m{"10.1.0.1": []string{"localhost:14243"}},
		"lighthouse":      m{"hosts": []string{"10.1.0.1"}, "interval": 1},
	})

	// Start a real local TCP echo server.
	echoAddr := echoServer(t)

	// Server exposes the echo server on its Nebula port 7001.
	logger := logrus.New()
	logger.Out = os.Stdout
	serverMgr := tunnel.New(serverSvc, logger)
	// Use the server's lifecycle context so exposeLoop is cancelled on cleanup.
	if err := serverMgr.StartExpose(serverSvc.Context(), tunnel.ExposeRule{
		Name:       "echo",
		ListenPort: 7001,
		Forward:    echoAddr,
	}); err != nil {
		t.Fatal(err)
	}

	// Client dials the server's Nebula IP:7001 directly (no access rule needed).
	var conn net.Conn
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = clientSvc.DialContext(context.Background(), "tcp", "10.1.0.1:7001")
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial through expose: %v", err)
	}
	defer conn.Close()

	// Read the greeting sent by the echo server.
	buf := make([]byte, 6)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !bytes.Equal(buf, []byte("hello\n")) {
		t.Fatalf("unexpected greeting: %q", buf)
	}

	// Send a message and verify it's echoed back.
	msg := []byte("nebula-tunnel\n")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echo, msg) {
		t.Fatalf("echo mismatch: got %q want %q", echo, msg)
	}
}

// TestAccess verifies that StartAccess makes a remote Nebula service
// reachable via a local listener on the client.
func TestAccess(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(
		cert.Version2, cert.Curve_CURVE25519,
		time.Now(), time.Now().Add(10*time.Minute),
		nil, nil, []string{},
	)

	// "server" node acts as lighthouse.
	serverSvc := newTestService(t, ca, caKey, netip.MustParseAddr("10.2.0.1"), m{
		"static_host_map": m{},
		"lighthouse":      m{"am_lighthouse": true},
		"listen":          m{"host": "0.0.0.0", "port": 14244},
	})

	// "client" node.
	clientSvc := newTestService(t, ca, caKey, netip.MustParseAddr("10.2.0.2"), m{
		"static_host_map": m{"10.2.0.1": []string{"localhost:14244"}},
		"lighthouse":      m{"hosts": []string{"10.2.0.1"}, "interval": 1},
	})

	echoAddr := echoServer(t)

	logger := logrus.New()
	logger.Out = os.Stdout

	// Server exposes the echo server on Nebula port 7002.
	// Use each service's own lifecycle context so loops are cancelled on cleanup.
	serverMgr := tunnel.New(serverSvc, logger)
	if err := serverMgr.StartExpose(serverSvc.Context(), tunnel.ExposeRule{
		Name:       "echo",
		ListenPort: 7002,
		Forward:    echoAddr,
	}); err != nil {
		t.Fatal(err)
	}

	// Client sets up an access rule: localhost:17002 → server Nebula IP:7002.
	clientMgr := tunnel.New(clientSvc, logger)
	if err := clientMgr.StartAccess(clientSvc.Context(), tunnel.AccessRule{
		Name:      "echo-access",
		LocalPort: 17002,
		Remote:    "10.2.0.1:7002",
	}); err != nil {
		t.Fatal(err)
	}

	// Dial the local access port — should traverse the Nebula overlay.
	var conn net.Conn
	var err error
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.Dial("tcp", "127.0.0.1:17002")
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial access port: %v", err)
	}
	defer conn.Close()

	// Read greeting.
	buf := make([]byte, 6)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if !bytes.Equal(buf, []byte("hello\n")) {
		t.Fatalf("unexpected greeting: %q", buf)
	}

	// Verify echo.
	msg := []byte("through-tunnel\n")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echo, msg) {
		t.Fatalf("echo mismatch: got %q want %q", echo, msg)
	}
}

// TestLoadConfig verifies that LoadConfig correctly parses tunnel config.
func TestLoadConfig(t *testing.T) {
	raw := `
tunnel:
  expose:
    - name: web
      listen_port: 80
      forward: "127.0.0.1:8080"
  access:
    - name: db
      local_port: 5432
      remote: "10.0.0.5:5432"
`
	l := logrus.New()
	l.Out = os.Stdout
	c := config.NewC(l)
	if err := c.LoadString(raw); err != nil {
		t.Fatal(err)
	}

	cfg, err := tunnel.LoadConfig(c)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Expose) != 1 {
		t.Fatalf("want 1 expose rule, got %d", len(cfg.Expose))
	}
	if cfg.Expose[0].Name != "web" || cfg.Expose[0].ListenPort != 80 || cfg.Expose[0].Forward != "127.0.0.1:8080" {
		t.Fatalf("expose rule mismatch: %+v", cfg.Expose[0])
	}

	if len(cfg.Access) != 1 {
		t.Fatalf("want 1 access rule, got %d", len(cfg.Access))
	}
	if cfg.Access[0].Name != "db" || cfg.Access[0].LocalPort != 5432 || cfg.Access[0].Remote != "10.0.0.5:5432" {
		t.Fatalf("access rule mismatch: %+v", cfg.Access[0])
	}
}

// TestLoadConfigEmpty verifies that LoadConfig returns empty config when no
// "tunnel" section is present.
func TestLoadConfigEmpty(t *testing.T) {
	l := logrus.New()
	l.Out = os.Stdout
	c := config.NewC(l)
	if err := c.LoadString("pki:\n  ca: dummy\n"); err != nil {
		t.Fatal(err)
	}

	cfg, err := tunnel.LoadConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Expose) != 0 || len(cfg.Access) != 0 {
		t.Fatalf("expected empty config, got %+v", cfg)
	}
}
