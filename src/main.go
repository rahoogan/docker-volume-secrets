package main

import (
	"flag"

	"github.com/rs/zerolog"
)

func main() {
	isDebug := false
	flag.BoolVar(&isDebug, "debug", false, "Enable debugging")
	flag.Parse()

	// Configure logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if isDebug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	}

	// Plugin starts and listens on a unix socket
}
