package inference_engine


// DatabaseAccessor defines the interface for database operations
// that the InferenceService might need.
type DatabaseAccessor interface {
	// GetValue retrieves a value from the database by key.
	// This is an example method; define methods based on actual needs.
	GetValue(key string) (string, error)

	// SetValue stores a value in the database with a given key.
	// This is an example method; define methods based on actual needs.
	SetValue(key, value string) error
}
