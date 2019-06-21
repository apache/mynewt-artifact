// This is a thin wrapper over the `pkg/errors` package.  It decorates this
// package with the following functionality:
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
