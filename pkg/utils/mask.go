// MaskSensitiveMapRecursive returns a copy of the map with sensitive values masked,
// recursively masking nested maps as well
func MaskSensitiveMapRecursive(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}

	masked := make(map[string]interface{}, len(m))
	for k, v := range m {
		if IsSensitiveKey(k) {
			if sv, ok := v.(string); ok {
				masked[k] = MaskSensitiveValue(sv)
			} else {
				masked[k] = "[REDACTED]"
			}
		} else if subMap, ok := v.(map[string]interface{}); ok {
			masked[k] = MaskSensitiveMapRecursive(subMap)
		} else {
			masked[k] = v
		}
	}
	return masked
}