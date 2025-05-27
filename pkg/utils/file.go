// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// GetFileMode converts an integer mode to os.FileMode
func GetFileMode(mode int) os.FileMode {
	if mode == 0 {
		return 0644 // Default file permissions
	}
	return os.FileMode(mode)
}

// SetFileOwnership sets the owner, group, and permissions of a file
func SetFileOwnership(filePath, username, groupname string, mode os.FileMode) error {
	var uid, gid int = -1, -1

	// Resolve username to UID
	if username != "" {
		if u, err := user.Lookup(username); err == nil {
			if uid, err = strconv.Atoi(u.Uid); err != nil {
				return err
			}
		} else {
			// Try parsing as numeric UID
			if uid, err = strconv.Atoi(username); err != nil {
				return err
			}
		}
	}

	// Resolve group name to GID
	if groupname != "" {
		if g, err := user.LookupGroup(groupname); err == nil {
			if gid, err = strconv.Atoi(g.Gid); err != nil {
				return err
			}
		} else {
			// Try parsing as numeric GID
			if gid, err = strconv.Atoi(groupname); err != nil {
				return err
			}
		}
	}

	// Change ownership if UID or GID specified
	if uid != -1 || gid != -1 {
		if err := syscall.Chown(filePath, uid, gid); err != nil {
			return err
		}
	}

	// Change permissions if mode specified
	if mode != 0 {
		if err := os.Chmod(filePath, mode); err != nil {
			return err
		}
	}

	return nil
}
