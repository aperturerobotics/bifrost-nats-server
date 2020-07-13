// Copyright 2012-2019 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package logger provides logging facilities for the NATS server
package logger

import (
	"fmt"
	// "log"
	"os"
	"sync"

	"github.com/sirupsen/logrus"
)

// Logger is the server logger
type Logger struct {
	sync.Mutex
	logger *logrus.Entry
	debug  bool
	trace  bool
}

// NewStdLogger creates a logger with output directed to Stderr
func NewLogger(le *logrus.Entry, debug, trace, pid bool) *Logger {
	return &Logger{
		logger: le,
		debug:  debug,
		trace:  trace,
	}
}

type writerAndCloser interface {
	Write(b []byte) (int, error)
	Close() error
	Name() string
}

// NewTestLogger creates a logger with output directed to Stderr with a prefix.
// Useful for tracing in tests when multiple servers are in the same pid
func NewTestLogger(prefix string, time bool) *Logger {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	le := logrus.NewEntry(log)
	return &Logger{
		logger: le,
		debug:  true,
		trace:  true,
	}
}

// Close implements the io.Closer interface to clean up
// resources in the server's logger implementation.
// Caller must ensure threadsafety.
func (l *Logger) Close() error {
	return nil
}

// Generate the pid prefix string
func pidPrefix() string {
	return fmt.Sprintf("[%d] ", os.Getpid())
}

// Noticef logs a notice statement
func (l *Logger) Noticef(format string, v ...interface{}) {
	l.logger.Infof(format, v...)
}

// Warnf logs a notice statement
func (l *Logger) Warnf(format string, v ...interface{}) {
	l.logger.Warnf(format, v...)
}

// Errorf logs an error statement
func (l *Logger) Errorf(format string, v ...interface{}) {
	l.logger.Errorf(format, v...)
}

// Fatalf logs a fatal error
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.logger.Errorf("[FATAL] "+format, v...)
}

// Debugf logs a debug statement
func (l *Logger) Debugf(format string, v ...interface{}) {
	// if l.debug {}
	l.logger.Debugf(format, v...)
}

// Tracef logs a trace statement
func (l *Logger) Tracef(format string, v ...interface{}) {
	if l.trace {
		l.logger.Debugf("[TRACE] "+format, v...)
	}
}
