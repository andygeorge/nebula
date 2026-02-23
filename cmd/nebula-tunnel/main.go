// nebula-tunnel exposes local TCP services to a Nebula overlay network and
// makes remote Nebula services accessible locally, similar to Cloudflare Tunnel.
//
// Unlike the main nebula binary, nebula-tunnel runs in fully userspace mode
// (no TUN device, no root privileges required). It connects to the Nebula
// overlay via its UDP port and proxies individual TCP connections, not full
// Layer-3 traffic.
//
// Configuration extends the standard Nebula YAML with a "tunnel" section:
//
//	tunnel:
//	  expose:
//	    - name: web
//	      listen_port: 80        # port on your Nebula overlay IP
//	      forward: 127.0.0.1:8080  # local service to reach
//	  access:
//	    - name: remote-db
//	      local_port: 5432       # listen on localhost
//	      remote: 10.0.0.5:5432  # remote Nebula peer:port
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/service"
	"github.com/slackhq/nebula/tunnel"
	"github.com/slackhq/nebula/util"
)

// Build is optionally set at link time via -ldflags "-X main.Build=<version>".
var Build string

func init() {
	if Build == "" {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		Build = strings.TrimPrefix(info.Main.Version, "v")
	}
}

func main() {
	configPath := flag.String("config", "", "Path to either a file or directory to load configuration from")
	printVersion := flag.Bool("version", false, "Print version")
	printUsage := flag.Bool("help", false, "Print command line usage")

	flag.Parse()

	if *printVersion {
		fmt.Printf("Version: %s\n", Build)
		os.Exit(0)
	}

	if *printUsage {
		flag.Usage()
		os.Exit(0)
	}

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "-config flag must be set")
		flag.Usage()
		os.Exit(1)
	}

	l := logrus.New()
	l.Out = os.Stdout

	c := config.NewC(l)
	if err := c.Load(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %s\n", err)
		os.Exit(1)
	}

	// nebula-tunnel always uses the userspace overlay device — no TUN/root needed.
	ctrl, err := nebula.Main(c, false, Build, l, overlay.NewUserDeviceFromConfig)
	if err != nil {
		util.LogWithContextIfNeeded("Failed to start nebula", err, l)
		os.Exit(1)
	}

	// service.New starts the Nebula control loop and wraps it with a gvisor
	// userspace TCP/UDP stack so we can Listen/Dial over the overlay.
	svc, err := service.New(ctrl)
	if err != nil {
		l.WithError(err).Fatal("Failed to create nebula service")
	}

	cfg, err := tunnel.LoadConfig(c)
	if err != nil {
		l.WithError(err).Fatal("Invalid tunnel config")
	}

	if len(cfg.Expose) == 0 && len(cfg.Access) == 0 {
		l.Warn("No tunnel rules configured — add 'tunnel.expose' or 'tunnel.access' to your config")
	}

	mgr := tunnel.New(svc, l)
	ctx := ctrl.Context()

	for _, rule := range cfg.Expose {
		if err := mgr.StartExpose(ctx, rule); err != nil {
			l.WithError(err).WithField("name", rule.Name).Fatal("Failed to start expose endpoint")
		}
	}

	for _, rule := range cfg.Access {
		if err := mgr.StartAccess(ctx, rule); err != nil {
			l.WithError(err).WithField("name", rule.Name).Fatal("Failed to start access endpoint")
		}
	}

	// Block until SIGTERM/SIGINT, then shut down all tunnels and wait for
	// in-flight connections to drain.
	ctrl.ShutdownBlock()
	_ = svc.Wait()
}
