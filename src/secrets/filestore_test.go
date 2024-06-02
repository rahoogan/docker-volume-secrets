package secrets

import (
	"bytes"
	"encoding/hex"
	"fmt"
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

func TestSomething(t *testing.T) {
	testDir, err := os.MkdirTemp("", "test")
	if err != nil {
		t.Errorf("Could not create temp file dir (data) for test")
	}
	dataDir := filepath.Join(testDir, "data")
	secretsDir := filepath.Join(testDir, "secrets")

	driver := FileStoreDriver{
		DataPath:       dataDir,
		SecretsPath:    secretsDir,
		EncryptionType: AES256,
	}
	prompter := MockPasswordPrompter{prompt: "test prompt"}
	driver.Setup(&prompter)

	// check that password cache was created
	keyPath := filepath.Join(dataDir, fmt.Sprintf("%d", os.Geteuid()), "docker-secrets-volume", "master_key")
	_, err = os.Stat(keyPath)
	if err != nil {
		t.Errorf("master key file not created in: %s", keyPath)
	}
	masterKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Errorf("master key could not be read: %s", keyPath)
	}

	expectedKey := "feee1a53de36f31deae3c7a683a29ee58ab36c5a2533ab125e9fe413eda606920000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f52f8e9e34091844365ebf9182ff6dfc"

	data, _ := hex.DecodeString(expectedKey)
	if bytes.Equal(masterKey, data) {
		t.Errorf("Expected master key value: %v, Got: %v", masterKey, expectedKey)
	}

	// check that environment variables override the passed in args
	dataDir = filepath.Join(testDir, "data2")
	secretsDir = filepath.Join(testDir, "secrets2")
	os.Setenv("DOCKER_VOLUME_SECRETS_SECERT_PATH", secretsDir)
	os.Setenv("DOCKER_VOLUME_SECRETS_DATA_PATH", dataDir)
	os.Setenv("DOCKER_VOLUME_SECRETS_ENC_TYPE", string(AES128))
	driver.Setup(&prompter)
	if driver.DataPath != dataDir {
		t.Errorf("Data path not set from env var. Expected: %s, Got: %s", dataDir, driver.DataPath)
	}
	if driver.SecretsPath != secretsDir {
		t.Errorf("Secrets path not set from env var. Expected: %s, Got: %s", secretsDir, driver.SecretsPath)
	}
	if driver.EncryptionType != AES128 {
		t.Errorf("Encryption type not set from env var. Expected: %s, Got: %s", AES128, driver.EncryptionType)
	}
}
