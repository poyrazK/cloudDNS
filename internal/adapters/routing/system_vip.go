package routing

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"strings"

	"github.com/poyrazK/cloudDNS/internal/core/ports"
)

// commandExecutor allows mocking exec.Command for testing
type commandExecutor interface {
	Run(ctx context.Context, name string, arg ...string) ([]byte, error)
}

type realExecutor struct{}

func (e *realExecutor) Run(ctx context.Context, name string, arg ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, arg...).CombinedOutput()
}

// SystemVIPAdapter implements the VIPManager port by executing system commands
// to bind/unbind IP addresses to local interfaces.
type SystemVIPAdapter struct {
	logger   *slog.Logger
	executor commandExecutor
	os       string // for testing
}

// NewSystemVIPAdapter initializes a new SystemVIPAdapter.
func NewSystemVIPAdapter(logger *slog.Logger) *SystemVIPAdapter {
	if logger == nil {
		logger = slog.Default()
	}
	return &SystemVIPAdapter{
		logger:   logger,
		executor: &realExecutor{},
		os:       runtime.GOOS,
	}
}

// Bind attaches a VIP to the specified interface.
func (a *SystemVIPAdapter) Bind(ctx context.Context, vip, iface string) error {
	if net.ParseIP(vip) == nil {
		return fmt.Errorf("invalid VIP address: %s", vip)
	}
	if iface == "" {
		return fmt.Errorf("interface name cannot be empty")
	}

	var name string
	var args []string
	switch a.os {
	case "linux":
		name = "ip"
		args = []string{"addr", "add", vip + "/32", "dev", iface}
	case "darwin":
		name = "ifconfig"
		args = []string{iface, "alias", vip, "255.255.255.255"}
	default:
		return fmt.Errorf("unsupported OS for VIP management: %s", a.os)
	}

	output, err := a.executor.Run(ctx, name, args...)
	if err != nil {
		outStr := string(output)
		// Check for common "already exists" errors to make it idempotent
		if strings.Contains(outStr, "File exists") || strings.Contains(outStr, "already bound") {
			a.logger.Info("VIP already bound", "vip", vip, "iface", iface)
			return nil
		}
		a.logger.Warn("VIP bind command failed", "error", err, "vip", vip, "output", outStr)
		return fmt.Errorf("failed to bind VIP: %w (output: %s)", err, outStr)
	}

	a.logger.Info("bound VIP to interface", "vip", vip, "iface", iface)
	return nil
}

// Unbind removes a VIP from the specified interface.
func (a *SystemVIPAdapter) Unbind(ctx context.Context, vip, iface string) error {
	if net.ParseIP(vip) == nil {
		return fmt.Errorf("invalid VIP address: %s", vip)
	}
	if iface == "" {
		return fmt.Errorf("interface name cannot be empty")
	}

	var name string
	var args []string
	switch a.os {
	case "linux":
		name = "ip"
		args = []string{"addr", "del", vip + "/32", "dev", iface}
	case "darwin":
		name = "ifconfig"
		args = []string{iface, "-alias", vip}
	default:
		return a.handleUnsupportedOS()
	}

	output, err := a.executor.Run(ctx, name, args...)
	if err != nil {
		outStr := string(output)
		a.logger.Warn("VIP unbind command finished with error", "error", err, "vip", vip, "output", outStr)
		return fmt.Errorf("failed to unbind VIP: %w (output: %s)", err, outStr)
	}

	a.logger.Info("unbound VIP from interface", "vip", vip, "iface", iface)
	return nil
}

func (a *SystemVIPAdapter) handleUnsupportedOS() error {
	return fmt.Errorf("unsupported OS for VIP management: %s", a.os)
}

var _ ports.VIPManager = (*SystemVIPAdapter)(nil)
