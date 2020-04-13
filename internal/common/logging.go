package common

import (
	log "github.com/sirupsen/logrus"
)

func SetupLogging() {
	// Only log the warning severity or above.
	log.SetLevel(log.DebugLevel)

	Formatter := new(log.TextFormatter)
	Formatter.TimestampFormat = "2006-01-02 15:04:05"
	Formatter.FullTimestamp = true
	Formatter.ForceColors = true // for docker

	log.SetFormatter(Formatter)

	log.Debug("Logrus logger initialized..., loglevel: ", log.GetLevel())
}
