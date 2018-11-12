package logtag

import "log"

const (
	Debug = "[DEBUG]"
	Info = "[INFO]"
	Error = "[ERROR]"
	Fatal = "[FATAL]"
)

func LogRequestService (svc string) {
	log.Printf("%s Requesting %s service", Info, svc)
}