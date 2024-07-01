package main

import (
	"flag"
	"fmt"
	"os/user"
	"rahoogan/docker-secrets-volume/secrets/awssm"
	"rahoogan/docker-secrets-volume/volumes"

	"github.com/docker/go-plugins-helpers/volume"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	SOCKET_ADDRESS string = "/run/docker/plugins/dsv.sock"
)

func main() {
	isDebug := false
	flag.BoolVar(&isDebug, "debug", false, "Enable debugging")
	flag.Parse()

	// Check if plugin is running as root
	// TODO: Support rootless install
	currUser, err := user.Current()
	if err != nil {
		log.Error().Err(err).Msg("Could not verify if running as root")
	}
	if currUser.Username != "root" {
		log.Error().Err(err).Msg("Plugin needs to run as root")
		panic(1)
	}

	// Configure logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if isDebug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	}

	// Create and setup a SecretStore driver
	secretsBackend := awssm.AWSSecretsManagerDriver{
		RequestTimeout: 0,
		SecretsPath:    awssm.DEFAULT_DRIVER_SECRETS_PATH,
	}
	err = secretsBackend.Setup()
	if err != nil {
		log.Error().Err(err).Msg("Plugin could not be started")
		panic(1)
	}

	// Initialize a docker volume driver with the secretstore backend
	driver := volumes.DockerSecretsVolumeDriver{SecretBackend: &secretsBackend}

	// Plugin starts and listens on a unix socket
	handler := volume.NewHandler(&driver)
	fmt.Printf("Listening on %s\n", SOCKET_ADDRESS)
	handler.ServeUnix(SOCKET_ADDRESS, 0) // #nosec
}
