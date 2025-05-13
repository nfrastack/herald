package filter

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types"
)

// FilterType represents the type of filter to apply
type FilterType string

// Filter operation types
const (
	FilterOperationAND = "AND"
	FilterOperationOR  = "OR"
	FilterOperationNOT = "NOT"
)

// Available filter types
const (
	FilterTypeNone    FilterType = "none"    // No filtering
	FilterTypeLabel   FilterType = "label"   // Filter by container label
	FilterTypeName    FilterType = "name"    // Filter by container name
	FilterTypeNetwork FilterType = "network" // Filter by container network
	FilterTypeImage   FilterType = "image"   // Filter by container image
	FilterTypeService FilterType = "service" // Filter by service name (Swarm)
	FilterTypeHealth  FilterType = "health"  // Filter by container health status
)

// Filter defines a container filter
type Filter struct {
	Type      FilterType // Type of filter
	Value     string     // Filter value
	Operation string     // AND, OR, NOT (defaults to AND)
	Negate    bool       // Invert the filter result
}

// FilterConfig defines filter configuration
type FilterConfig struct {
	Filters []Filter // List of filters to apply
}

// DefaultFilterConfig returns a default filter configuration
func DefaultFilterConfig() FilterConfig {
	return FilterConfig{
		Filters: []Filter{
			{
				Type:  FilterTypeNone,
				Value: "",
			},
		},
	}
}

// NewFilterFromOptions creates a filter from options
func NewFilterFromOptions(options map[string]string) (FilterConfig, error) {
	// Check if we have a simple filter
	filterType, hasFilterType := options["filter_type"]
	filterValue, hasFilterValue := options["filter_value"]

	// Default to no filtering
	config := DefaultFilterConfig()

	// If we have a simple filter
	if hasFilterType && filterType != "" {
		if filterType != string(FilterTypeNone) && (!hasFilterValue || filterValue == "") {
			return config, fmt.Errorf("filter_value is required when filter_type is not 'none'")
		}

		config.Filters = []Filter{
			{
				Type:      FilterType(filterType),
				Value:     filterValue,
				Operation: FilterOperationAND,
				Negate:    false,
			},
		}
	}

	// Look for advanced filters in options
	const filterPrefix = "filter."
	for key, value := range options {
		if !strings.HasPrefix(key, filterPrefix) {
			continue
		}

		// Format: filter.N.type, filter.N.value, filter.N.operation, filter.N.negate
		parts := strings.SplitN(key[len(filterPrefix):], ".", 2)
		if len(parts) != 2 {
			continue
		}

		// We don't need to use the filter index, just need to validate the format
		filterProp := parts[1]

		// Find existing filter or create new one
		var found bool
		for i := range config.Filters {
			if config.Filters[i].Type == FilterTypeNone {
				// Replace the default filter
				config.Filters[i].Type = FilterType(value)
				found = true
				break
			}
		}

		if !found {
			// Add new filter
			newFilter := Filter{
				Type:      FilterType(value),
				Operation: FilterOperationAND, // Default to AND
				Negate:    false,
			}
			config.Filters = append(config.Filters, newFilter)
		}

		// Set filter property based on key suffix
		switch filterProp {
		case "type":
			config.Filters[len(config.Filters)-1].Type = FilterType(value)
		case "value":
			config.Filters[len(config.Filters)-1].Value = value
		case "operation":
			config.Filters[len(config.Filters)-1].Operation = strings.ToUpper(value)
		case "negate":
			config.Filters[len(config.Filters)-1].Negate = strings.ToLower(value) == "true"
		}
	}

	return config, nil
}

// ShouldProcessContainer determines if a container should be processed based on the filters
func (fc FilterConfig) ShouldProcessContainer(container types.ContainerJSON) bool {
	// If no filters or just the "none" filter, process all containers
	if len(fc.Filters) == 0 || (len(fc.Filters) == 1 && fc.Filters[0].Type == FilterTypeNone) {
		return true
	}

	// Process filters with AND/OR logic
	var result bool
	for i, filter := range fc.Filters {
		// Check if this filter matches
		match := matchFilter(filter, container)

		// Apply NOT if needed
		if filter.Negate {
			match = !match
		}

		// For the first filter, just set the result
		if i == 0 {
			result = match
			continue
		}

		// Apply operation
		switch filter.Operation {
		case FilterOperationAND:
			result = result && match
		case FilterOperationOR:
			result = result || match
		case FilterOperationNOT:
			result = result && !match
		default:
			// Default to AND
			result = result && match
		}
	}

	return result
}

// matchFilter checks if a container matches a single filter
func matchFilter(filter Filter, container types.ContainerJSON) bool {
	switch filter.Type {
	case FilterTypeNone:
		return true

	case FilterTypeLabel:
		return matchLabelFilter(filter.Value, container)

	case FilterTypeName:
		return matchNameFilter(filter.Value, container)

	case FilterTypeNetwork:
		return matchNetworkFilter(filter.Value, container)

	case FilterTypeImage:
		return matchImageFilter(filter.Value, container)

	case FilterTypeService:
		return matchServiceFilter(filter.Value, container)

	case FilterTypeHealth:
		return matchHealthFilter(filter.Value, container)

	default:
		// Unknown filter type, don't match
		return false
	}
}

// matchLabelFilter checks if a container matches a label filter
func matchLabelFilter(filterValue string, container types.ContainerJSON) bool {
	// Filter value can be either "label" or "label=value"
	parts := strings.SplitN(filterValue, "=", 2)
	labelName := parts[0]

	// Check if the label exists
	labelValue, hasLabel := container.Config.Labels[labelName]
	if !hasLabel {
		return false
	}

	// If we're just checking for label existence
	if len(parts) == 1 {
		return true
	}

	// Check if the label value matches
	labelPattern := parts[1]

	// Check for wildcard matches
	if strings.Contains(labelPattern, "*") {
		// Convert glob pattern to regex
		regexPattern := "^" + strings.Replace(strings.Replace(regexp.QuoteMeta(labelPattern), "\\*", ".*", -1), "\\?", ".", -1) + "$"
		match, err := regexp.MatchString(regexPattern, labelValue)
		if err != nil {
			// In case of regex error, just do a direct compare
			return labelValue == labelPattern
		}
		return match
	}

	// Direct comparison
	return labelValue == labelPattern
}

// matchNameFilter checks if a container matches a name filter
func matchNameFilter(filterValue string, container types.ContainerJSON) bool {
	// Clean container name (remove leading slash)
	containerName := container.Name
	if strings.HasPrefix(containerName, "/") {
		containerName = containerName[1:]
	}

	// Check for wildcard matches
	if strings.Contains(filterValue, "*") || strings.Contains(filterValue, "?") {
		matched, err := filepath.Match(filterValue, containerName)
		if err != nil {
			// If pattern is invalid, fall back to direct comparison
			return containerName == filterValue
		}
		return matched
	}

	// Direct comparison
	return containerName == filterValue
}

// matchNetworkFilter checks if a container belongs to a specific network
func matchNetworkFilter(filterValue string, container types.ContainerJSON) bool {
	// Check each network the container is connected to
	for networkName := range container.NetworkSettings.Networks {
		// Direct name match
		if networkName == filterValue {
			return true
		}

		// Wildcard match
		if strings.Contains(filterValue, "*") || strings.Contains(filterValue, "?") {
			matched, err := filepath.Match(filterValue, networkName)
			if err != nil {
				continue // Invalid pattern, try next network
			}
			if matched {
				return true
			}
		}
	}
	return false
}

// matchImageFilter checks if a container's image matches the filter
func matchImageFilter(filterValue string, container types.ContainerJSON) bool {
	// Get container image name
	imageName := container.Config.Image

	// Check for direct match
	if imageName == filterValue {
		return true
	}

	// Check for wildcard match
	if strings.Contains(filterValue, "*") || strings.Contains(filterValue, "?") {
		matched, err := filepath.Match(filterValue, imageName)
		if err != nil {
			// If pattern is invalid, fall back to direct comparison
			return imageName == filterValue
		}
		return matched
	}

	return false
}

// matchServiceFilter checks if a container belongs to a specific service (Swarm)
func matchServiceFilter(filterValue string, container types.ContainerJSON) bool {
	// Check for Docker Swarm service labels
	serviceName, hasServiceName := container.Config.Labels["com.docker.swarm.service.name"]
	if !hasServiceName {
		return false
	}

	// Check for direct match
	if serviceName == filterValue {
		return true
	}

	// Check for wildcard match
	if strings.Contains(filterValue, "*") || strings.Contains(filterValue, "?") {
		matched, err := filepath.Match(filterValue, serviceName)
		if err != nil {
			// If pattern is invalid, fall back to direct comparison
			return serviceName == filterValue
		}
		return matched
	}

	return false
}

// matchHealthFilter checks if a container's health status matches the filter
func matchHealthFilter(filterValue string, container types.ContainerJSON) bool {
	if container.State == nil {
		return false
	}

	// If container has no health check, return true only if filter value is "none"
	if container.State.Health == nil {
		return strings.ToLower(filterValue) == "none"
	}

	// Check health status
	healthStatus := container.State.Health.Status
	return strings.ToLower(healthStatus) == strings.ToLower(filterValue)
}
