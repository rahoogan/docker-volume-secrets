package volumes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"rahoogan/docker-secrets-volume/secrets"

	"github.com/containers/podman/v2/pkg/ctime"
	"github.com/docker/go-plugins-helpers/volume"
	"github.com/rs/zerolog/log"
)

const (
	DRIVER_INSTALL_PATH string = "/docker/plugins/data" // The location where the plugin is installed
)

var (
	DEFAULT_SECRETS_PATH string = filepath.Join(DRIVER_INSTALL_PATH, "secrets")
)

type DockerSecretsVolumeDriver struct {
	SecretBackend secrets.SecretStoreDriver
}

func getSecretPath(secretName string) string {
	return filepath.Join(DEFAULT_SECRETS_PATH, secretName)
}

func (driver *DockerSecretsVolumeDriver) checkSecretOk(secretName string) error {
	secretPath := filepath.Clean(getSecretPath(secretName))

	// Verify secret has been registered with volume plugin
	_, err := os.ReadFile(secretPath)
	if err != nil && os.IsNotExist(err) {
		log.Error().Err(err).Msg("Secret volume does not exist. Create it using 'docker volume create' first.")
		return err
	} else if err != nil {
		log.Error().Err(err).Msg("corrupted secret volume. Try deleting and recreating")
		return err
	}

	// Check that secret still exists in secrets backend
	getRequest := secrets.GetSecret{Name: secretName}
	_, err = driver.SecretBackend.Get(&getRequest)
	if err != nil {
		log.Error().Err(err).Msg("Secret volume does not exist. Create it using 'docker volume create' first.")
		return err
	}
	return nil
}

// This function registers a new secret with the volume driver
// The secret must be uniquely identified by the Name in the secrets backend
// and must exist in the secrets backend, other wise this request will fail
// The secret is not stored on disk at this stage, that happens during mount
func (driver *DockerSecretsVolumeDriver) Create(request *volume.CreateRequest) error {
	getRequest := secrets.GetSecret{Name: request.Name}
	_, err := driver.SecretBackend.Get(&getRequest)
	if err != nil {
		log.Error().Err(err).Msg("The secret does not exist in the secrets backend")
		return err
	}

	// Check if mountpoint for secrets volume with same name already exists
	secretPath := filepath.Clean(getSecretPath(request.Name))
	_, err = os.ReadFile(secretPath)
	if err != nil && os.IsNotExist(err) {
		// Create empty file for mountpoint to indicate that secret volume has been created
		_, err := os.Create(secretPath)
		if err != nil {
			log.Error().Err(err).Msg("Could not create mountpoint for secret")
			return err
		}
	} else if err == nil {
		err = errors.New("could not create secret volume. A volume with that name already exists")
		log.Error().Err(err)
		return err
	} else {
		err = errors.New("unexpected error when creating volume")
		log.Error().Err(err)
		return err
	}
	return nil
}

// This function checks if the secret exists in the secret backend and that
// the Create function has been called to register the secret with the
// volume plugin. If so, it returns the source mountpoint where the secret
// will be mounted to when Mount is called.
func (driver *DockerSecretsVolumeDriver) Get(request *volume.GetRequest) (*volume.GetResponse, error) {
	getResponse := volume.GetResponse{}

	if err := driver.checkSecretOk(request.Name); err != nil {
		return &getResponse, err
	}
	getResponse.Volume = &volume.Volume{Name: request.Name, Mountpoint: getSecretPath(request.Name)}
	return &getResponse, nil
}

// This function lists all the secrets registered with the volume plugin
// It DOES NOT list all the secrets in the secrets backend
func (driver *DockerSecretsVolumeDriver) List() (*volume.ListResponse, error) {
	files, err := os.ReadDir(DEFAULT_SECRETS_PATH)
	if err != nil {
		log.Error().Err(err).Msg("Could not read secrets dir")
		return &volume.ListResponse{Volumes: make([]*volume.Volume, 0)}, err
	}
	volumeList := []*volume.Volume{}
	for _, file := range files {
		if !file.IsDir() {
			fileInfo, err := file.Info()
			if err != nil {
				log.Warn().Msg(fmt.Sprintf("Corrupt secret file: %s", file.Name()))
			} else {
				item := volume.Volume{
					Name:       file.Name(),
					Mountpoint: getSecretPath(file.Name()),
					CreatedAt:  ctime.Created(fileInfo).String(),
				}
				volumeList = append(volumeList, &item)
			}
		}
	}
	return &volume.ListResponse{Volumes: volumeList}, nil
}

// This function removes the secret registered with the volume plugin
// This DOES NOT remove the secret from the secrets backend
func (driver *DockerSecretsVolumeDriver) Remove(request *volume.RemoveRequest) error {
	secretMountPath := getSecretPath(request.Name)
	if _, err := os.Stat(secretMountPath); err == nil {
		// Delete secret file at mount path
		if err := os.Remove(secretMountPath); err != nil {
			log.Error().Err(err).Msg("Volume could not be deleted")
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Error().Err(err).Msg("Volume could not be deleted: error checking for file")
		return err
	} else if errors.Is(err, os.ErrNotExist) {
		log.Error().Err(err).Msg("Volume does not exist")
		return err
	}
	return nil
}

// This function provides the mountpoint where the secret is mounted
// (or will be mounted)
func (driver *DockerSecretsVolumeDriver) Path(request *volume.PathRequest) (*volume.PathResponse, error) {
	pathResponse := volume.PathResponse{}
	if err := driver.checkSecretOk(request.Name); err != nil {
		return &pathResponse, err
	}
	pathResponse.Mountpoint = getSecretPath(request.Name)
	return &pathResponse, nil
}

// This function fetches the secret from the secrets backend and writes
// it to a file on disk so that it can be mounted into a container
func (driver *DockerSecretsVolumeDriver) Mount(request *volume.MountRequest) (*volume.MountResponse, error) {
	mountResponse := volume.MountResponse{}
	if err := driver.checkSecretOk(request.Name); err != nil {
		return &mountResponse, err
	}
	// Fetch the secret from the secrets backend
	getRequest := secrets.GetSecret{Name: request.Name}
	secret, err := driver.SecretBackend.Get(&getRequest)
	if err != nil {
		return &mountResponse, err
	}
	// Write the secret to the volume source mount path
	mountPath := getSecretPath(request.Name)
	err = os.WriteFile(mountPath, []byte(secret.Secret.Value), 0400)
	if err != nil {
		return nil, err
	}
	mountResponse.Mountpoint = mountPath
	return &mountResponse, nil
}

// This function does not need to do anything.
// It could be improved by checking if there are any containers using
// the volume and trying to delete the mount file if not
func (driver *DockerSecretsVolumeDriver) Unmount(request *volume.UnmountRequest) error {
	return nil
}

func (driver *DockerSecretsVolumeDriver) Capabilities() *volume.CapabilitiesResponse {
	return &volume.CapabilitiesResponse{Capabilities: volume.Capability{Scope: "local"}}
}
