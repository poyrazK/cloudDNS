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

// SystemVIPAdapter implements the VIPManager port by executing system commands
// to bind/unbind IP addresses to local interfaces.
type SystemVIPAdapter struct {
	logger *slog.Logger
}

// NewSystemVIPAdapter initializes a new SystemVIPAdapter.
func NewSystemVIPAdapter(logger *slog.Logger) *SystemVIPAdapter {
	if logger == nil {
		logger = slog.Default()
	}
	return &SystemVIPAdapter{logger: logger}
}

// Bind attaches a VIP to the specified interface.
func (a *SystemVIPAdapter) Bind(ctx context.Context, vip, iface string) error {
	if net.ParseIP(vip) == nil {
		return fmt.Errorf("invalid VIP address: %s", vip)
	}
	if iface == "" {
		return fmt.Errorf("interface name cannot be empty")
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		// ip addr add 1.1.1.1/32 dev lo
		// #nosec G204
		cmd = exec.CommandContext(ctx, "ip", "addr", "add", vip+"/32", "dev", iface)
	case "darwin":
		// ifconfig lo0 alias 1.1.1.1 255.255.255.255
		// #nosec G204
		cmd = exec.CommandContext(ctx, "ifconfig", iface, "alias", vip, "255.255.255.255")
	default:
		return fmt.Errorf("unsupported OS for VIP management: %s", runtime.GOOS)
	}

	output, err := cmd.CombinedOutput()
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

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		// #nosec G204
		cmd = exec.CommandContext(ctx, "ip", "addr", "del", vip+"/32", "dev", iface)
	case "darwin":
		// #nosec G204
		cmd = exec.CommandContext(ctx, "ifconfig", iface, "-alias", vip)
	default:
		return a.handleUnsupportedOS()
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		outStr := string(output)
		// Ignore if it's already gone? No, usually Unbind should be explicit.
		// But for robustness we can log and return error.
		a.logger.Warn("VIP unbind command finished with error", "error", err, "vip", vip, "output", outStr)
		return fmt.Errorf("failed to unbind VIP: %w (output: %s)", err, outStr)
	}

	a.logger.Info("unbound VIP from interface", "vip", vip, "iface", iface)
	return nil
}

func (a *SystemVIPAdapter) handleUnsupportedOS() error {
	return fmt.Errorf("unsupported OS for VIP management: %s", runtime.GOOS)
}

var _ ports.VIPManager = (*SystemVIPAdapter)(nil)
