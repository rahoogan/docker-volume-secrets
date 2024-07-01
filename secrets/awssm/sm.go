package awssm

import (
	"errors"
	"os"
	"path/filepath"
	"rahoogan/docker-secrets-volume/secrets"
	"rahoogan/docker-secrets-volume/volumes"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	"github.com/rs/zerolog/log"
)

const (
	AWSSecretAccessKeyVar   string = "AWS_SECRET_ACCESS_KEY"
	AWSSecretAccessKeyIdVar string = "AWS_ACCESS_KEY_ID"
	AWSRegionNameVar        string = "AWS_REGION"
	AWSEndpointUrlVar       string = "AWS_ENDPOINT_URL"
	AWSProfileVar           string = "AWS_PROFILE"
)

var DEFAULT_DRIVER_SECRETS_PATH string = filepath.Join(volumes.DRIVER_INSTALL_PATH, "secrets")

type AWSSecretsManagerDriver struct {
	SecretsPath        string
	AWSEndpoint        string
	AWSAccessKeyId     string
	AWSSecretAccessKey string
	AWSRegion          string
	SecretCache        *secretcache.Cache
	RequestTimeout     int
}

// Ensure a directory exists by creating it if it doesn't exist
func ensureDir(dirName string, mode os.FileMode) error {
	log.Debug().Msg("Creating directory: " + dirName)
	err := os.MkdirAll(dirName, mode)
	if err != nil {
		log.Error().Err(err).Msg("Error making directory")
		return err
	}
	return nil
}

// Sets up the secretsmanager cache and client
func (driver *AWSSecretsManagerDriver) Setup() error {
	err := ensureDir(driver.SecretsPath, 0755)
	if err != nil {
		log.Error().Err(err).Msg("Could not create secrets dir")
		return err
	}
	// Get credentials for profile
	driver.AWSAccessKeyId = os.Getenv(AWSSecretAccessKeyIdVar)
	driver.AWSSecretAccessKey = os.Getenv(AWSSecretAccessKeyVar)
	driver.AWSRegion = os.Getenv(AWSRegionNameVar)
	driver.AWSEndpoint = os.Getenv(AWSEndpointUrlVar)

	if driver.AWSAccessKeyId == "" || driver.AWSSecretAccessKey == "" || driver.AWSRegion == "" {
		return errors.New("you must set aws credential env vars for the plugin to work")
	}
	cconfig := secretcache.CacheConfig{
		MaxCacheSize: secretcache.DefaultMaxCacheSize,
		VersionStage: secretcache.DefaultVersionStage,
		CacheItemTTL: secretcache.DefaultCacheItemTTL,
	}
	client := secretsmanager.New(secretsmanager.Options{BaseEndpoint: aws.String(driver.AWSEndpoint), Region: driver.AWSRegion})
	driver.SecretCache, err = secretcache.New(
		func(c *secretcache.Cache) { c.CacheConfig = cconfig },
		func(c *secretcache.Cache) { c.Client = client },
	)
	if err != nil {
		return err
	}
	return nil
}

// Fetches the secret from secretsmanager
// throws an error if secret doesn't exist
func (driver *AWSSecretsManagerDriver) Create(createrequest *secrets.CreateSecret) error {
	// Fetch secret from AWS secretsmanager to verify it exists
	// but don't store it locally yet
	_, err := driver.SecretCache.GetSecretString(createrequest.Name)
	if err != nil {
		log.Error().Err(err).Msg("Could not create secret volume. The secret does not exist in AWS secretsmanager")
		return err
	}
	return nil
}

// This retrieves details of a secret stored in secretsmanager.
// The secret will not exist at the mountpoint unless a container has
// mounted the secret, The mountpoint provided here is an empty
// placeholder file
func (driver *AWSSecretsManagerDriver) Get(getrequest *secrets.GetSecret) (secretresponse *secrets.GetSecretResponse, err error) {
	secretValue, err := driver.SecretCache.GetSecretString(getrequest.Name)
	if err != nil {
		log.Error().Err(err).Msg("Could not fetch remote secret")
		return &secrets.GetSecretResponse{}, err
	}
	return &secrets.GetSecretResponse{Secret: secrets.Secret{Name: getrequest.Name, Value: secretValue}}, err
}
