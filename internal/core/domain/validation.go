package domain

import (
	"fmt"
	"regexp"
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
