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
	"runtime"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const AES_KEY_LENGTH int = 32
const AES_GCM_NONCE_LENGTH int = 12

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

func cacheEncryptionKey(key []byte, passwordName string, passwordDir string) error {
	// Caches encryption key to file
	// TODO: Security - update this to use keyring/keychain or don't cache at all
	switch goos := runtime.GOOS; goos {
	case "darwin":
	case "linux":
		err := ensureDir(passwordDir, 0700)
		if err != nil {
			log.Warn().Err(err).Msg("Could not cache encryption key")
			return err
		}
		err = os.WriteFile(filepath.Join(passwordDir, passwordName), key, 0600)
		if err != nil {
			log.Warn().Err(err).Msg("Could not cache encryption key")
			return err
		}
	}
	return nil
}

func getCachedEncryptionKey(passwordName string, passwordDir string) ([]byte, error) {
	switch goos := runtime.GOOS; goos {
	case "darwin":
	case "linux":
		key, err := os.ReadFile(filepath.Join(passwordDir, passwordName))
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, nil
}

func getEncryptionKey(prompter Prompter, cachePath string, randGenerator Generator) (key []byte, err error) {
	key, _ = getCachedEncryptionKey("master_key", cachePath)
	if key == nil {
		pwd, err := prompter.PromptForData("password: ")
		if err != nil {
			log.Error().Err(err).Msg("Could not read password")
			return nil, err
		}
		key, err = deriveKey(pwd, AES_KEY_LENGTH, randGenerator)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

func deriveKey(passwordString string, keySize int, randGenerator Generator) (key []byte, err error) {
	// Convert password to encryption key
	// argon2 is the latest key derivation function
	key = make([]byte, keySize+aes.BlockSize)
	saltData := key[keySize : keySize+aes.BlockSize]
	err = randGenerator.GenerateData(saltData, aes.BlockSize)
	if err != nil {
		log.Error().Err(err).Msg("Error deriving key from password: could not generate random salt")
	}
	keyData := argon2.IDKey([]byte(passwordString), saltData, 1, 64*1024, 4, 32)
	copy(key[:32], keyData[:])
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
