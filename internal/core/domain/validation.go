package domain

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var validLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ValidateZoneName checks if the provided zone name is a valid FQDN.
func ValidateZoneName(name string) error {
	if name == "" {
		return fmt.Errorf("zone name cannot be empty")
	}
	if name == "." {
		return nil // Root zone is valid
	}
	if !strings.HasSuffix(name, ".") {
		return fmt.Errorf("zone name must end with a dot (FQDN)")
	}
	if len(name) > 254 {
		return fmt.Errorf("zone name exceeds 253 characters")
	}

	// Remove trailing dot for label validation
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("label '%s' exceeds 63 characters", label)
		}
		if label == "" {
			return fmt.Errorf("zone name contains empty label")
		}
		if !validLabelRegex.MatchString(label) {
			return fmt.Errorf("label '%s' contains invalid characters or format", label)
		}
	}
	return nil
}

// ValidateSRVContent ensures SRV content follows "priority weight port target" format.
// Used for non-API inputs like zone-file imports.
func ValidateSRVContent(content string) error {
	parts := strings.Fields(content)
	if len(parts) != 4 {
		return fmt.Errorf("SRV content must be in format: priority weight port target")
	}

	for i, name := range []string{"priority", "weight", "port"} {
		val, err := strconv.Atoi(parts[i])
		if err != nil || val < 0 || val > 65535 {
			return fmt.Errorf("invalid %s: %s (must be 0-65535)", name, parts[i])
		}
	}

	target := parts[3]
	if !strings.HasSuffix(target, ".") {
		return fmt.Errorf("target must be a FQDN (end with a dot)")
	}

	return nil
}

// ValidateSRVFields validates SRV fields individually. Used for API inputs.
func ValidateSRVFields(priority, weight, port *int, target string) error {
	if priority == nil || weight == nil || port == nil {
		return fmt.Errorf("SRV record requires priority, weight, and port fields")
	}
	if *priority < 0 || *priority > 65535 {
		return fmt.Errorf("invalid priority: %d (must be 0-65535)", *priority)
	}
	if *weight < 0 || *weight > 65535 {
		return fmt.Errorf("invalid weight: %d (must be 0-65535)", *weight)
	}
	if *port < 0 || *port > 65535 {
		return fmt.Errorf("invalid port: %d (must be 0-65535)", *port)
	}
	if !strings.HasSuffix(target, ".") {
		return fmt.Errorf("SRV target must be a FQDN (end with a dot)")
	}
	return nil
}
