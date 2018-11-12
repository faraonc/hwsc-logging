package logtag

import (
	"log"
	"strings"
)

const (
	Debug = "[DEBUG]"
	Info = "[INFO]"
	Error = "[ERROR]"
	Fatal = "[FATAL]"
)

func LogRequestService (svc string) {
	log.Printf("%s Requesting %s service", Info, svc)
}

func LogInfo (args ...string) {
	log.Printf("%s %s", Info, strings.Join(args, " "))
}

func LogFatal (args ...string) {
	log.Printf("%s %s", Fatal, strings.Join(args, " "))
}