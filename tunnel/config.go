package tunnel

import (
	"fmt"

	"github.com/slackhq/nebula/config"
	"go.yaml.in/yaml/v3"
)

// Config holds tunnel rules for exposing and accessing services over the Nebula overlay.
type Config struct {
	// Expose lists local services to make accessible to Nebula peers.
	Expose []ExposeRule `yaml:"expose"`
	// Access lists remote Nebula services to make accessible locally.
	Access []AccessRule `yaml:"access"`
}

// ExposeRule exposes a local TCP service to the Nebula overlay network.
// Other Nebula peers can connect to your Nebula IP at ListenPort and reach Forward.
type ExposeRule struct {
	// Name is a human-readable label for logging and diagnostics.
	Name string `yaml:"name"`
	// ListenPort is the TCP port on the Nebula overlay to listen on.
	ListenPort int `yaml:"listen_port"`
	// Forward is the local address (host:port) to forward Nebula connections to.
	Forward string `yaml:"forward"`
}

// AccessRule creates a local TCP listener that proxies connections through the
// Nebula overlay to a remote peer's exposed service.
type AccessRule struct {
	// Name is a human-readable label for logging and diagnostics.
	Name string `yaml:"name"`
	// LocalPort is the TCP port to listen on locally (bound to 127.0.0.1).
	LocalPort int `yaml:"local_port"`
	// Remote is the Nebula overlay address (nebulaIP:port) of the target service.
	Remote string `yaml:"remote"`
}

// LoadConfig parses tunnel configuration from the Nebula config under the "tunnel" key.
// Returns an empty Config (no error) if no "tunnel" section is present.
func LoadConfig(c *config.C) (*Config, error) {
	raw := c.Get("tunnel")
	if raw == nil {
		return &Config{}, nil
	}

	// Re-marshal through YAML to get typed struct fields.
	data, err := yaml.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal tunnel config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal tunnel config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	for i, r := range c.Expose {
		if r.ListenPort <= 0 || r.ListenPort > 65535 {
			return fmt.Errorf("expose[%d] %q: invalid listen_port %d", i, r.Name, r.ListenPort)
		}
		if r.Forward == "" {
			return fmt.Errorf("expose[%d] %q: forward must not be empty", i, r.Name)
		}
	}
	for i, r := range c.Access {
		if r.LocalPort <= 0 || r.LocalPort > 65535 {
			return fmt.Errorf("access[%d] %q: invalid local_port %d", i, r.Name, r.LocalPort)
		}
		if r.Remote == "" {
			return fmt.Errorf("access[%d] %q: remote must not be empty", i, r.Name)
		}
	}
	return nil
}
