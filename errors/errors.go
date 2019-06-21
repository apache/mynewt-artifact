/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// This is a thin wrapper over the `pkg/errors` package.  It decorates the
// base package with the following functionality:
//
// 1. Wrap and Wrapf produce an error with exactly one stack trace.  If the
// wrapped error already contains a stack trace, these functions just append
// text to the message.
//
// 2. WithStack produces an error with exactly one stack trace.  If the
// wrapped error already contains a stack trace, this function returns it
// unmodified.

package errors

import (
	"fmt"

	pkgerrors "github.com/pkg/errors"
)

type stackTracer interface {
	StackTrace() pkgerrors.StackTrace
}

// Cause retrieves the underlying cause of an error
func Cause(err error) error {
	return pkgerrors.Cause(err)
}

// Errorf formats according to a format specifier and returns the string
// as a value that satisfies error.
// Errorf also records the stack trace at the point it was called.
func Errorf(format string, args ...interface{}) error {
	return pkgerrors.Errorf(format, args...)
}

// New returns an error with the supplied message.
// New also records the stack trace at the point it was called.
func New(message string) error {
	return pkgerrors.New(message)
}

// Wrap returns an error annotating err with a stack trace at the point Wrap is
// called, and the supplied message.  If err is nil, Wrap returns nil.
func Wrap(err error, message string) error {
	if _, ok := err.(stackTracer); !ok {
		return pkgerrors.Wrap(err, message)
	} else {
		msg := err.Error() + ": " + message
		return pkgerrors.WithMessage(err, msg)
	}
}

// Wrapf returns an error annotating err with a stack trace at the point Wrapf
// is called, and the format specifier.  If err is nil, Wrapf returns nil.
func Wrapf(err error, format string, args ...interface{}) error {
	return Wrap(err, fmt.Sprintf(format, args...))
}

// WithStack annotates err with a stack trace at the point WithStack was called.
// If err is nil, WithStack returns nil.
func WithStack(err error) error {
	if _, ok := err.(stackTracer); !ok {
		return pkgerrors.WithStack(err)
	} else {
		return err
	}
}

// HasStackTrace tells you if the given error contains a stack trace.
func HasStackTrace(err error) bool {
	_, ok := err.(stackTracer)
	return ok
}
