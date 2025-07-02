// This file ensures all input provider subtypes are registered.
// It should be in the input package, but separate from input.go to avoid import cycles.
// No other code should import subtypes directly; only this file should do so.

package input

import (
	_ "herald/pkg/input/types/caddy"
	_ "herald/pkg/input/types/docker"
	_ "herald/pkg/input/types/zerotier"
	_ "herald/pkg/input/types/file"
	// Add more providers here as needed
)
