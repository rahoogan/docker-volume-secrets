package secrets

// Stores all details about a secret
type Secret struct {
	Name       string
	Value      string
	Mountpoint string
	Options    map[string]string `json:"Opts,omitempty"`
}

// The type to request to store a new secret
type CreateSecret struct {
	Secret Secret
}

// The type to request a secret value
type GetSecret struct {
	Name string
}

// The response type for requests to get a secret value
type GetSecretResponse struct {
	Secret Secret
}

// Type to store non-confidential details about a secret
type SecretMetadata struct {
	Name       string
	Mountpoint string
	Options    map[string]string `json:"Opts,omitempty"`
}

// The response type for a request to list secrets
type ListSecretResponse struct {
	Secrets []SecretMetadata
}

// The type to request deleting a secret
type DeleteSecret struct {
	Name string
}

// The type to request mounting a secret
type MountSecret struct {
	Name string
}

// This is the interface which all secretstore plugins must fulfil
type SecretStoreDriver interface {
	Setup(Generator) error                       // Run any setup for the secrets backend
	Create(*CreateSecret) error                  // Store a secret in the secrets backend
	Get(*GetSecret) (*GetSecretResponse, error)  // Get a secret value from the backend
	Mount(*MountSecret) (*SecretMetadata, error) // Save the unencrypted secret value to a file in the mountpath
	List() (*ListSecretResponse, error)          // List all secrets
	Delete(*DeleteSecret) error                  // Delete a secret from the backend
}

const (
	DRIVER_MOUNT_PATH   string = "/run/docker/plugins/dsv/mounts" // The location where unencrypted secrets are stored for mounting by volumes
	DRIVER_INSTALL_PATH string = "/var/lib/docker/plugins/dsv"    // The location where the plugin is installed
)
