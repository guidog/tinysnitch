package log

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type Handler func(format string, args ...interface{})

const (
	DEBUG = iota
	INFO
	IMPORTANT
	WARNING
	ERROR
	FATAL
)

var (
	Output     = os.Stdout
	DateFormat = "2006-01-02 15:04:05"
	MinLevel   = INFO

	mutex  = &sync.Mutex{}
	labels = map[int]string{
		DEBUG:     "DBG",
		INFO:      "INF",
		IMPORTANT: "IMP",
		WARNING:   "WAR",
		ERROR:     "ERR",
		FATAL:     "!!!",
	}
)

func Wrap(s, effect string) string {
	return s
}

func Dim(s string) string {
	return s
}

func Bold(s string) string {
	return s
}

func Red(s string) string {
	return s
}

func Green(s string) string {
	return s
}

func Blue(s string) string {
	return s
}

func Yellow(s string) string {
	return s
}

func Raw(format string, args ...interface{}) {
	mutex.Lock()
	defer mutex.Unlock()
	fmt.Fprintf(Output, format, args...)
}

func Log(level int, format string, args ...interface{}) {
	if level >= MinLevel {
		mutex.Lock()
		defer mutex.Unlock()
		label := labels[level]
		when := time.Now().UTC().Format(DateFormat)
		what := fmt.Sprintf(format, args...)
		if strings.HasSuffix(what, "\n") == false {
			what += "\n"
		}
		fmt.Fprintf(Output, "%s %s %s", when, label, what)
	}
}

func Debug(format string, args ...interface{}) {
	Log(DEBUG, format, args...)
}

func Info(format string, args ...interface{}) {
	Log(INFO, format, args...)
}

func Important(format string, args ...interface{}) {
	Log(IMPORTANT, format, args...)
}

func Warning(format string, args ...interface{}) {
	Log(WARNING, format, args...)
}

func Error(format string, args ...interface{}) {
	Log(ERROR, format, args...)
}

func Fatal(format string, args ...interface{}) {
	Log(FATAL, format, args...)
	os.Exit(1)
}
