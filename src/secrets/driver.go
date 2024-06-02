package secrets

type Secret struct {
	Name    string
	Value   string
	Options map[string]string `json:"Opts,omitempty"`
}

type CreateSecret struct {
	Secret Secret
}

type GetSecret struct {
	Name string
}

type GetSecretResponse struct {
	Secret Secret
}

type SecretMetadata struct {
	Name    string
	Options map[string]string `json:"Opts,omitempty"`
}

type ListSecretResponse struct {
	Secrets []SecretMetadata
}

type DeleteSecret struct {
	Name string
}

// This is the interface which all secretstore plugins must fulfil
type SecretStoreDriver interface {
	Setup() error
	Create(*CreateSecret) error
	Get(*GetSecret) (*GetSecretResponse, error)
	List() (*ListSecretResponse, error)
	Delete(*DeleteSecret) error
}
