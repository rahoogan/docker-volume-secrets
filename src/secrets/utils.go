package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	RANDOM_DATA_LENGTH       = 50
	AES_KEY_LENGTH       int = 32
	AES_GCM_NONCE_LENGTH int = 12
)

func ensureDir(dirName string, mode os.FileMode) error {
	err := os.MkdirAll(dirName, mode)
	if err != nil {
		log.Error().Err(err).Msg("Error making directory")
		return err
	}
	return nil
}

type PasswordPrompter struct {
	prompt string
}

func (prompter *PasswordPrompter) PromptForData(prompt string) (data string, err error) {
	prompter.prompt = prompt
	fmt.Printf("%s: ", prompt)
	pwd, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(pwd), nil
}

type RandomGenerator struct{}

func (generator *RandomGenerator) GenerateData(dataContainer []byte, length int) error {
	if _, err := io.ReadFull(rand.Reader, dataContainer); err != nil {
		return err
	}
	return nil
}

func deriveKey(randomData []byte, keySize int, randGenerator Generator) (key []byte, err error) {
	// Convert password to encryption key
	// argon2 is the latest key derivation function
	key = make([]byte, keySize+aes.BlockSize)
	saltData := key[keySize : keySize+aes.BlockSize]
	err = randGenerator.GenerateData(saltData, aes.BlockSize)
	if err != nil {
		log.Error().Err(err).Msg("Error deriving key from password: could not generate random salt")
	}
	keyData := argon2.IDKey(randomData, saltData, 1, 64*1024, 4, 32)
	copy(key[:32], keyData[:])
	return key, nil
}

func getEncryptionKey(driver *FileStoreDriver) (key []byte, err error) {
	keyPath := filepath.Join(driver.DataPath, fmt.Sprintf("%s_%s", MASTER_KEY_NAME, driver.EncryptionType))
	// Create a random encryption key if one does not exist
	file, _ := os.Stat(keyPath)
	if file == nil || (!file.IsDir()) {
		randomData := make([]byte, RANDOM_DATA_LENGTH)
		err = driver.RandomGenerator.GenerateData(randomData, RANDOM_DATA_LENGTH)
		if err != nil {
			log.Error().Err(err).Msg("Could not generate random data for encryption key")
			return nil, err
		}
		encKey, err := deriveKey(randomData, keyLengthBytes[driver.EncryptionType], driver.RandomGenerator)
		if err == nil {
			err = os.WriteFile(keyPath, encKey, 0600)
			if err != nil {
				log.Error().Err(err).Msg("Could not write encryption key")
				return nil, err
			}
			return encKey, nil
		} else {
			log.Error().Err(err).Msg("Could not generate encryption key")
			return nil, err
		}
	}
	key, err = os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func encryptWithKey(encryptionKey []byte, keySize int, randGenerator Generator, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey[:keySize])
	if err != nil {
		log.Error().Err(err).Msg("Error encrypting data: could not initialize encryption key")
		return nil, err
	}

	nonce := make([]byte, AES_GCM_NONCE_LENGTH)
	err = randGenerator.GenerateData(nonce, AES_GCM_NONCE_LENGTH)
	if err != nil {
		log.Error().Err(err).Msg("Error encrypting data: could not generate random nonce")
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Error().Err(err).Msg("Error encrypting data: could not create new AES GCM")
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	ciphertext = append(nonce, ciphertext...)

	return ciphertext, nil
}

func decryptWithKey(encryptionKey []byte, keySize int, ciphertext []byte) (plaintext string, err error) {
	block, err := aes.NewCipher(encryptionKey[:keySize])
	if err != nil {
		log.Error().Err(err).Msg("Error decrypting data: could not initialize encryption key")
		return "", err
	}

	if len(ciphertext) < AES_GCM_NONCE_LENGTH {
		err := errors.New("error decrypting data: ciphertext is too short")
		log.Error().Err(err)
		return "", err
	}

	nonce := ciphertext[:AES_GCM_NONCE_LENGTH]
	ciphertext = ciphertext[AES_GCM_NONCE_LENGTH:]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Error().Err(err).Msg("Error decrypting data: could not initialize encryption key")
	}
	plaintextData, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Error().Err(err).Msg("Error decrypting data: could not decrypt using key")
	}
	return string(plaintextData), nil
}
