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

type FileStoreDriver struct {
	DataPath        string
	SecretsPath     string
	EncryptionType  EncryptionAlgorithm
	RandomGenerator Generator
}

type Prompter interface {
	PromptForData(prompt string) (data string, err error)
}

type Generator interface {
	GenerateData(dataContainer []byte, length int) error
}

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
	key, err := getEncryptionKey(driver)
	if err != nil {
		return err
	}
	if key == nil {
		err := errors.New("got empty encryption key. cannot setup plugin")
		return err
	}
	return nil
}

func (driver *FileStoreDriver) Create(createrequest *CreateSecret) error {
	key, _ := getEncryptionKey(driver)
	if key == nil {
		err := errors.New("could not get encryption key for generating secret")
		log.Error().Err(err).Msg("")
		return err
	}

	encryptedData, err := encryptWithKey(key, AES_KEY_LENGTH, driver.RandomGenerator, []byte(createrequest.Secret.Value))
	if err != nil {
		return err
	}

	secretFile := filepath.Join(driver.SecretsPath, createrequest.Secret.Name)

	file, err := os.Stat(secretFile)
	if file != nil && !file.IsDir() && err == nil {
		err := errors.New("secret already exists")
		return err
	}

	err = os.WriteFile(secretFile, encryptedData, 0600)
	if err != nil {
		log.Error().Err(err).Msg("Could not create secret")
		return err
	}
	return nil
}

func (driver *FileStoreDriver) Get(getrequest *GetSecret) (secretresponse GetSecretResponse, err error) {
	key, _ := getEncryptionKey(driver)
	if key == nil {
		err := errors.New("could not get encryption key for retrieving secret")
		log.Error().Err(err).Msg("")
		return GetSecretResponse{}, err
	}
	ciphertext, err := os.ReadFile(filepath.Join(driver.SecretsPath, getrequest.Name))
	if err != nil {
		log.Error().Err(err).Msg("Could not read secret file")
		return GetSecretResponse{}, err
	}
	plaintext, err := decryptWithKey(key, AES_KEY_LENGTH, ciphertext)
	if err != nil {
		log.Error().Err(err).Msg("Could not decrypt secret file")
		return GetSecretResponse{}, err
	}
	return GetSecretResponse{Secret: Secret{Name: getrequest.Name, Value: plaintext}}, nil
}

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
			item := SecretMetadata{Name: file.Name()}
			secrets = append(secrets, item)
		}
	}
	resp.Secrets = secrets
	return &resp, nil
}

func (driver *FileStoreDriver) Delete(deleterequest *DeleteSecret) error {
	secretPath := filepath.Join(driver.SecretsPath, deleterequest.Name)
	if _, err := os.Stat(secretPath); err == nil {
		// Delete secret file
		if err := os.Remove(secretPath); err != nil {
			log.Error().Err(err).Msg("Secret could not be deleted: error removing secret file")
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Error().Err(err).Msg("Secret could not be deleted: error checking for secret file")
		return err
	}
	return nil
}
