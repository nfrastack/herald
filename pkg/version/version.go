// Package version provides version information for the application
package version

import "fmt"

// Info contains version information
var (
	// Version is the current version of the application
	Version = "development"

	// BuildTime is when the application was built
	BuildTime = "unknown"
)

// String returns a string representation of the version information
func String() string {
	return fmt.Sprintf("%s (built on %s)", Version, BuildTime)
}
