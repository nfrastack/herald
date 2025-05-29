package formats

import (
	"os"
	"os/user"
	"strconv"
	"syscall"

	"dns-companion/pkg/log"
)

// setFileOwnership is a common helper function to set file ownership and permissions
func setFileOwnership(filePath string, config map[string]interface{}, logger *log.ScopedLogger) error {
	// Set file ownership if specified
	if userConfig, ok := config["user"].(string); ok && userConfig != "" {
		var uid int
		var gid int = -1 // Keep existing group by default

		// Look up user
		if u, err := user.Lookup(userConfig); err == nil {
			if parsed, err := strconv.Atoi(u.Uid); err == nil {
				uid = parsed
				if parsed, err := strconv.Atoi(u.Gid); err == nil {
					gid = parsed // Use user's primary group as fallback
				}
			}
		} else {
			logger.Warn("Failed to lookup user '%s': %v", userConfig, err)
		}

		// Override group if specified
		if groupConfig, ok := config["group"].(string); ok && groupConfig != "" {
			if g, err := user.LookupGroup(groupConfig); err == nil {
				if parsed, err := strconv.Atoi(g.Gid); err == nil {
					gid = parsed
				}
			} else {
				logger.Warn("Failed to lookup group '%s': %v", groupConfig, err)
			}
		}

		// Apply ownership
		if err := syscall.Chown(filePath, uid, gid); err != nil {
			logger.Warn("Failed to change ownership of %s: %v", filePath, err)
		}
	}

	// Set file mode if specified
	if modeConfig, ok := config["mode"]; ok {
		var mode os.FileMode
		switch v := modeConfig.(type) {
		case int:
			mode = os.FileMode(v)
		case float64:
			mode = os.FileMode(int(v))
		case string:
			if parsed, err := strconv.ParseUint(v, 8, 32); err == nil {
				mode = os.FileMode(parsed)
			}
		}

		if mode != 0 {
			if err := os.Chmod(filePath, mode); err != nil {
				logger.Warn("Failed to change mode of %s: %v", filePath, err)
			}
		}
	}

	return nil
}