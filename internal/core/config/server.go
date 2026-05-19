package config

import (
	"time"
)

// ServerConfig holds timeout and timing values for the DNS server.
// All values have sensible defaults suitable for production use.
type ServerConfig struct {
	// UDPSocketReadDeadline is the read deadline set on UDP sockets to allow
	// periodic re-checking of the shutdown signal. Default: 500ms.
	UDPSocketReadDeadline time.Duration

	// ShutdownTimeout is the timeout for gracefully shutting down the server.
	// Default: 5 seconds.
	ShutdownTimeout time.Duration

	// RecursiveTimeout is the maximum time allowed for recursive resolution.
	// Default: 30 seconds.
	RecursiveTimeout time.Duration

	// HealthCheckInterval is the interval between health monitor checks.
	// Default: 30 seconds.
	HealthCheckInterval time.Duration

	// HealthCheckHTTPTimeout is the HTTP client timeout for health probes.
	// Default: 5 seconds.
	HealthCheckHTTPTimeout time.Duration

	// HealthCheckTCPTimeout is the TCP dial timeout for TCP health probes.
	// Default: 3 seconds.
	HealthCheckTCPTimeout time.Duration

	// BGPRouterID is the BGP router identifier. Default: "127.0.0.1".
	BGPRouterID string

	// BGPListenPort is the port GoBGP listens on. Default: 179.
	BGPListenPort int32

	// BGPNextHop is the next hop address for BGP announcements. Default: "127.0.0.1".
	BGPNextHop string
}

// DefaultServerConfig returns a ServerConfig with all values set to defaults.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		UDPSocketReadDeadline:   500 * time.Millisecond,
		ShutdownTimeout:         5 * time.Second,
		RecursiveTimeout:        30 * time.Second,
		HealthCheckInterval:     30 * time.Second,
		HealthCheckHTTPTimeout:  5 * time.Second,
		HealthCheckTCPTimeout:   3 * time.Second,
		BGPRouterID:             "127.0.0.1",
		BGPListenPort:            179,
		BGPNextHop:               "127.0.0.1",
	}
}