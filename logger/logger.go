package logger

import (
	"log"
	"strings"
)

const (
	LogTagDebug = "[DEBUG]"
	LogTagInfo = "[INFO]"
	LogTagError = "[ERROR]"
	LogTagFatal = "[FATAL]"
)

func RequestService (svc string) {
	log.Printf("%s Requesting %s service", LogTagInfo, svc)
}

func Info (args ...string) {
	log.Printf("%s %s", LogTagInfo, strings.Join(args, " "))
}

func Error (args ...string) {
	log.Printf("%s %s", LogTagError, strings.Join(args, " "))
}

func Fatal (args ...string) {
	log.Fatalf("%s %s", LogTagFatal, strings.Join(args, " "))
}
