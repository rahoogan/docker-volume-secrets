package secrets

// Stores all details about a secret
type Secret struct {
	Name    string
	Value   string
	Options map[string]string `json:"Opts,omitempty"`
}

// The type to request to store a new secret
type CreateSecret struct {
	// Prevent sending the actual secret value
	// in this request.
	// The idea is to create the secret outside
	// of the plugin using the secure methods
	// provided by your choice of secret backend
	Name string
}

// The type to request a secret value
type GetSecret struct {
	Name string
}

// The response type for requests to get a secret value
type GetSecretResponse struct {
	Secret Secret
}

// This is the interface which all secretstore plugins must fulfil
type SecretStoreDriver interface {
	Setup() error                               // Run any setup for the secrets backend
	Create(*CreateSecret) error                 // Store a secret in the secrets backend
	Get(*GetSecret) (*GetSecretResponse, error) // Get a secret value from the backend
}
