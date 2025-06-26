package domain

// OutputWriter defines the interface for writing/removing DNS records to output providers.
// This interface is defined in the domain package to break import cycles.
type OutputWriter interface {
	WriteRecordToOutputs(allowedOutputs []string, domain, hostname, target, recordType string, ttl int, source string) error
	RemoveRecordFromOutputs(allowedOutputs []string, domain, hostname, recordType, source string) error
}

// OutputSyncer defines the interface for syncing output providers.
// This is separate because BatchProcessor needs to trigger a sync.
type OutputSyncer interface {
	SyncAllFromSource(source string) error
}