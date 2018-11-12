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

func LogGeneral (args ...string) {
	log.Printf("%s", strings.Join(args, " "))
}