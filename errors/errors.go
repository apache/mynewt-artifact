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

// Errorf formats an error
func Errorf(format string, args ...interface{}) error {
	return pkgerrors.Errorf(format, args...)
}

// New creates a new error
func New(message string) error {
	return pkgerrors.New(message)
}

func Wrap(err error, message string) error {
	if _, ok := err.(stackTracer); !ok {
		return pkgerrors.Wrap(err, message)
	} else {
		msg := err.Error() + ": " + message
		return pkgerrors.WithMessage(err, msg)
	}
}

func Wrapf(err error, format string, args ...interface{}) error {
	return Wrap(err, fmt.Sprintf(format, args...))
}

func WithStack(err error) error {
	if _, ok := err.(stackTracer); !ok {
		return pkgerrors.WithStack(err)
	} else {
		return err
	}
}

func HasStackTrace(err error) bool {
	_, ok := err.(stackTracer)
	return ok
}
