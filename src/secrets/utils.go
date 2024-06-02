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

func (prompter *PasswordPrompter) PromptForData(prompt string) (string, error) {
	prompter.prompt = prompt
	fmt.Printf("%s: ", prompt)
	pwd, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(pwd), nil
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

func getEncryptionKey(prompter Prompter, cachePath string, encryptionType EncryptionAlgorithm) (key []byte, err error) {
	key, _ = getCachedEncryptionKey("master_key", cachePath)
	if key == nil {
		pwd, err := prompter.PromptForData("password: ")
		if err != nil {
			log.Error().Err(err).Msg("Could not read password")
			return nil, err
		}
		key, err = deriveKey(pwd, keyLengths[encryptionType])
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

func deriveKey(passwordString string, keySize int) (key []byte, err error) {
	// Convert password to encryption key
	// argon2 is the latest key derivation function
	key = make([]byte, keySize+aes.BlockSize)
	saltData := key[keySize : keySize+aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, saltData); err != nil {
		log.Error().Err(err).Msg("Error deriving key from password: could not generate random salt")
		return nil, err
	}
	keyData := argon2.IDKey([]byte(passwordString), saltData, 1, 64*1024, 4, 32)
	copy(key[:32], keyData[:])
	return key, nil
}

func encryptWithKey(encryptionKey []byte, keySize int, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey[:keySize])
	if err != nil {
		log.Error().Err(err).Msg("Error initializing encryption key")
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Error().Err(err).Msg("Error encrypting data: could not generate random iv")
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// TODO: Security - Sign with private key for authN
	// See: https://pkg.go.dev/crypto/cipher#NewCBCEncrypter
	return ciphertext, nil
}

func decryptWithKey(encryptionKey []byte, keySize int, ciphertext []byte) (plaintext string, err error) {
	block, err := aes.NewCipher(encryptionKey[:keySize])
	if err != nil {
		log.Error().Err(err).Msg("Error initializing encryption key")
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		err := errors.New("ciphertext is too short, cannot decrypt")
		log.Error().Err(err)
		return "", err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	plaintextData := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintextData, ciphertext)

	return string(plaintextData), nil
}
