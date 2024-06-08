package secrets

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
)

type EncryptionAlgorithm string

const (
	AES128 EncryptionAlgorithm = "aes128"
	AES192 EncryptionAlgorithm = "aes192"
	AES256 EncryptionAlgorithm = "aes256"
)

const (
	DEFAULT_SECRET_PATH      string              = "/run/docker/plugins/docker-secrets-volume/secrets"
	DEFAULT_SECRET_DATA_PATH string              = "/run/docker/plugins/docker-secrets-volume/data"
	DEFAULT_ENCRYPTION_TYPE  EncryptionAlgorithm = AES256
	MASTER_KEY_NAME          string              = "master_key"
)

var (
	keyLengthBytes = map[EncryptionAlgorithm]int{
		AES128: 16,
		AES192: 24,
		AES256: 32,
	}
)

// An implementation of the SecretStore driver which stores secrets encrypted on disk
type FileStoreDriver struct {
	DataPath        string
	SecretsPath     string
	EncryptionType  EncryptionAlgorithm
	RandomGenerator Generator
}

// A generic interface to describe a method to prompt a user for data
type Prompter interface {
	PromptForData(prompt string) (data string, err error)
}

// A generic interface to describe a method to generate data of a fixed size
type Generator interface {
	GenerateData(dataContainer []byte, length int) error
}

// Setup runs any steps required to setup the secrets backend.
// Typically, this would be run before using any of the other functions
func (driver *FileStoreDriver) Setup(dataGenerator Generator) error {
	secretPath, ok := os.LookupEnv("DOCKER_VOLUME_SECRETS_SECERT_PATH")
	if !ok {
		if driver.DataPath == "" {
			secretPath = DEFAULT_SECRET_PATH
		} else {
			secretPath = driver.SecretsPath
		}
	}
	dataPath, ok := os.LookupEnv("DOCKER_VOLUME_SECRETS_DATA_PATH")
	if !ok {
		if driver.DataPath == "" {
			dataPath = DEFAULT_SECRET_DATA_PATH
		} else {
			dataPath = driver.DataPath
		}
	}
	encAlg := driver.EncryptionType
	encType, ok := os.LookupEnv("DOCKER_VOLUME_SECRETS_ENC_TYPE")
	if ok {
		switch encType {
		case "AES128":
		case "aes128":
			encAlg = AES128
		case "AES192":
		case "aes192":
			encAlg = AES192
		}
	}
	driver.EncryptionType = encAlg

	// Set secret storage location
	driver.DataPath = dataPath
	driver.SecretsPath = secretPath
	driver.RandomGenerator = dataGenerator

	err := ensureDir(driver.DataPath, 0755)
	if err != nil {
		return err
	}
	err = ensureDir(driver.SecretsPath, 0755)
	if err != nil {
		return err
	}
	key, err := getOrCreateEncryptionKey(driver)
	if err != nil {
		return err
	}
	if key == nil {
		err := errors.New("got empty encryption key. cannot setup plugin")
		return err
	}
	return nil
}

// Create stores a new secret in the secrets backend.
// An error will be raised if the secret already exists (with the same name)
func (driver *FileStoreDriver) Create(createrequest *CreateSecret) error {
	key, _ := getOrCreateEncryptionKey(driver)
	if key == nil {
		err := errors.New("could not get encryption key for generating secret")
		log.Error().Err(err).Msg("")
		return err
	}

	encryptedData, err := encryptWithKey(key, keyLengthBytes[driver.EncryptionType], driver.RandomGenerator, []byte(createrequest.Secret.Value))
	if err != nil {
		return err
	}

	secretFile := filepath.Join(driver.SecretsPath, createrequest.Secret.Name)

	file, err := os.Stat(secretFile)
	if file != nil && !file.IsDir() && err == nil {
		err := errors.New("secret already exists")
		return err
	}

	err = os.WriteFile(secretFile, encryptedData, 0400)
	if err != nil {
		log.Error().Err(err).Msg("Could not create secret")
		return err
	}
	return nil
}

// Get retrieves the details of a secret stored in the secrets backend
func (driver *FileStoreDriver) Get(getrequest *GetSecret) (secretresponse *GetSecretResponse, err error) {
	key, _ := getOrCreateEncryptionKey(driver)
	if key == nil {
		err := errors.New("could not get encryption key for retrieving secret")
		log.Error().Err(err).Msg("")
		return &GetSecretResponse{}, err
	}
	secretPath := filepath.Join(driver.SecretsPath, getrequest.Name)
	ciphertext, err := os.ReadFile(secretPath)
	if err != nil {
		log.Error().Err(err).Msg("Could not read secret file")
		return &GetSecretResponse{}, err
	}
	plaintext, err := decryptWithKey(key, keyLengthBytes[driver.EncryptionType], ciphertext)
	if err != nil {
		log.Error().Err(err).Msg("Could not decrypt secret file")
		return &GetSecretResponse{}, err
	}
	return &GetSecretResponse{Secret: Secret{Name: getrequest.Name, Value: plaintext, Mountpoint: secretPath}}, nil
}

// List lists all secrets stored in the secrets backend
func (driver *FileStoreDriver) List() (listresponse *ListSecretResponse, err error) {
	files, err := os.ReadDir(driver.SecretsPath)
	if err != nil {
		log.Error().Err(err).Msg("Could not read secrets dir")
		return &ListSecretResponse{Secrets: make([]SecretMetadata, 0)}, err
	}
	secrets := []SecretMetadata{}
	resp := ListSecretResponse{Secrets: secrets}
	for _, file := range files {
		if !file.IsDir() {
			item := SecretMetadata{Name: file.Name(), Mountpoint: file.Type().String()}
			secrets = append(secrets, item)
		}
	}
	resp.Secrets = secrets
	return &resp, nil
}

// Delete deletes the secret from the secret backend and cleans up any mount files
func (driver *FileStoreDriver) Delete(deleterequest *DeleteSecret) error {
	secretPath := filepath.Join(driver.SecretsPath, deleterequest.Name)
	if _, err := os.Stat(secretPath); err == nil {
		// Delete secret file
		if err := os.Remove(secretPath); err != nil {
			log.Error().Err(err).Msg("Secret could not be deleted")
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Error().Err(err).Msg("Secret could not be deleted: error checking for secret file")
		return err
	}
	mountPath := filepath.Join(DRIVER_MOUNT_PATH, deleterequest.Name)
	if _, err := os.Stat(mountPath); err == nil {
		// Delete mount path
		if err := os.Remove(mountPath); err != nil {
			log.Error().Err(err).Msg("Secret mount could not be deleted")
			return err
		}
	}
	return nil
}

// Mount retrieves the plaintext secret value from the secrets backend
// and stores it in a file in the plugin's mount directory, ready for mounting.
func (driver *FileStoreDriver) Mount(mountrequest *MountSecret) (*SecretMetadata, error) {
	secret, err := driver.Get((*GetSecret)(mountrequest))
	if err != nil {
		return nil, err
	}
	// Don't overwrite existing file
	mountPath := filepath.Join(DRIVER_MOUNT_PATH, mountrequest.Name)
	if _, err = os.Stat(mountPath); os.IsNotExist(err) {
		err = os.WriteFile(mountPath, []byte(secret.Secret.Value), 0400)
		if err != nil {
			return nil, err
		}
	}
	return &SecretMetadata{Name: mountrequest.Name, Mountpoint: mountPath}, nil
}
