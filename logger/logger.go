package logger

import (
	"log"
	"strings"
)

const (
	// LogTagDebug debug tag
	LogTagDebug = "[DEBUG]"
	// LogTagInfo informational tag
	LogTagInfo = "[INFO]"
	// LogTagError error tag
	LogTagError = "[ERROR]"
	// LogTagFatal failure tag
	LogTagFatal = "[FATAL]"
)

// RequestService logs service request
func RequestService(svc string) {
	log.Printf("%s Requesting %s service", LogTagInfo, svc)
}

// Info provides informational logging
func Info(args ...string) {
	log.Printf("%s %s", LogTagInfo, strings.Join(args, " "))
}

// Error provides error logging
func Error(args ...string) {
	log.Printf("%s %s", LogTagError, strings.Join(args, " "))
}

// Fatal provides failure logging and shutting down application
func Fatal(args ...string) {
	log.Fatalf("%s %s", LogTagFatal, strings.Join(args, " "))
}
