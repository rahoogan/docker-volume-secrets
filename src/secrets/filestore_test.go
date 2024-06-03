package secrets

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
)

type MockPasswordPrompter struct {
	prompt string
}

func (prompter *MockPasswordPrompter) PromptForData(prompt string) (data string, err error) {
	return "test_password", nil
}

type MockRandomGenerator struct {
	name string
}

func (generator *MockRandomGenerator) GenerateData(dataContainer []byte, length int) error {
	for i := range dataContainer {
		dataContainer[i] = 1
	}
	return nil
}

type TestSetupData struct {
	driver     FileStoreDriver
	dataDir    string
	secretsDir string
	testDir    string
	prompter   MockPasswordPrompter
	generator  MockRandomGenerator
}

func SetupDriver() TestSetupData {
	setupData := TestSetupData{}
	testDir, err := os.MkdirTemp("", "test")
	if err != nil {
		log.Fatal("Could not create temp file dir (data) for test")
	} else {
		setupData.testDir = testDir
	}
	setupData.dataDir = filepath.Join(setupData.testDir, "data")
	setupData.secretsDir = filepath.Join(setupData.testDir, "secrets")

	driver := FileStoreDriver{
		DataPath:       setupData.dataDir,
		SecretsPath:    setupData.secretsDir,
		EncryptionType: AES256,
	}
	setupData.prompter = MockPasswordPrompter{prompt: "test prompt"}
	setupData.generator = MockRandomGenerator{name: "mocked"}
	driver.Setup(&setupData.prompter, &setupData.generator)
	setupData.driver = driver
	return setupData
}

func TestSecretsSetup(t *testing.T) {
	setupData := SetupDriver()
	// Expect that password cache file was created
	keyPath := filepath.Join(setupData.dataDir, fmt.Sprintf("%d", os.Geteuid()), "docker-secrets-volume", "master_key")
	_, err := os.Stat(keyPath)
	if err != nil {
		t.Errorf("master key file not created in: %s", keyPath)
	}
	masterKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Errorf("master key could not be read: %s", keyPath)
	}

	// Expect AES256 master key by default
	expectedKey := "842efc60a69ec827bfa16e85a4486a0dc5d3e9a3e20857ded768f0c6fee4498d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101"

	data, _ := hex.DecodeString(expectedKey)
	if err != nil {
		t.Errorf("Error decoding master key hexstring")
	}
	if len(masterKey) != 272 {
		t.Errorf("Expected key length: %v, Got: %v", 272, len(masterKey))
	}
	if !bytes.Equal(masterKey, data) {
		t.Errorf("Expected master key value: %x, Got: %v", expectedKey, masterKey)
	}

	// Expect salt of length 16 to be appended at the end of key
	expectedSalt := "01010101010101010101010101010101"
	data, err = hex.DecodeString(expectedSalt)
	if err != nil {
		t.Errorf("Error decoding salt hexstring")
	}
	salt := masterKey[256:]
	if !bytes.Equal(salt, data) {
		t.Errorf("Expected salt value: %x, Got: %x", expectedSalt, salt)
	}

	// Expect that environment variables override the passed in args
	setupData.dataDir = filepath.Join(setupData.testDir, "data2")
	setupData.secretsDir = filepath.Join(setupData.testDir, "secrets2")

	t.Setenv("DOCKER_VOLUME_SECRETS_SECERT_PATH", setupData.secretsDir)
	t.Setenv("DOCKER_VOLUME_SECRETS_DATA_PATH", setupData.dataDir)
	t.Setenv("DOCKER_VOLUME_SECRETS_ENC_TYPE", string(AES128))

	setupData.driver.Setup(&setupData.prompter, &setupData.generator)

	if setupData.driver.DataPath != setupData.dataDir {
		t.Errorf("Data path not set from env var. Expected: %s, Got: %s", setupData.dataDir, setupData.driver.DataPath)
	}
	if setupData.driver.SecretsPath != setupData.secretsDir {
		t.Errorf("Secrets path not set from env var. Expected: %s, Got: %s", setupData.secretsDir, setupData.driver.SecretsPath)
	}
	if setupData.driver.EncryptionType != AES128 {
		t.Errorf("Encryption type not set from env var. Expected: %s, Got: %s", AES128, setupData.driver.EncryptionType)
	}

	// Expect AES128 key to be created
	keyPath = filepath.Join(setupData.dataDir, fmt.Sprintf("%d", os.Geteuid()), "docker-secrets-volume", "master_key")
	masterKey, err = os.ReadFile(keyPath)
	if err != nil {
		t.Errorf("master key could not be read: %s", keyPath)
	}
	if len(masterKey) != 144 {
		t.Errorf("Expected key length: %v, Got: %v", 144, len(masterKey))
	}
}

func TestSecretCreate(t *testing.T) {
	setupData := SetupDriver()
	createRequest := CreateSecret{Secret{Name: "cow", Value: "moo"}}
	err := setupData.driver.Create(&createRequest)
	if err != nil {
		t.Errorf("Expected: secret to be created without error. Got: %v", err)
	}

	// Expect a secret file to be created
	keyPath := filepath.Join(setupData.secretsDir, "cow")
	_, pathError := os.Stat(keyPath)
	if pathError != nil {
		t.Errorf("Expected secret file to be created in: %s, Got: %v", keyPath, pathError)
	}

	expectedEncryptedSecret := "01010101010101010101010145c0333d50048b7c01068006eab989bb7970b0"
	expectedData, err := hex.DecodeString(expectedEncryptedSecret)
	if err != nil {
		t.Errorf("Error decoding secret string: %v", err)
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Errorf("Expected to read data from encrypted file, Got: %v", err)
	}
	if !bytes.Equal(data, expectedData) {
		t.Errorf("Expected encrypted data %x, Got: %x", expectedData, data)
	}
}

func TestSecretGet(t *testing.T) {
	setupData := SetupDriver()
	createRequest := CreateSecret{Secret{Name: "horse", Value: "neigh"}}
	err := setupData.driver.Create(&createRequest)
	if err != nil {
		t.Errorf("Expected: secret to be created without error. Got: %v", err)
	}
	getRequest := GetSecret{Name: "horse"}
	secret, err := setupData.driver.Get(&getRequest)
	if err != nil {
		t.Errorf("Expected nil error when creating crete, Got: %v", err)
	}
	if secret.Secret.Name != "horse" {
		t.Errorf("Expected secret name: horse, Got: %s", secret.Secret.Name)
	}
	if secret.Secret.Value != "neigh" {
		t.Errorf("Expected secret value: neigh, Got: %s", secret.Secret.Value)
	}
}

func TestSecretList(t *testing.T) {

}

func TestDelete(t *testing.T) {

}
