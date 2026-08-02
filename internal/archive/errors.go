package archive

import (
	"errors"
	"fmt"
)

// ErrorKind identifies failures that callers need to map to an HTTP status.
type ErrorKind string

const (
	KindInvalid     ErrorKind = "invalid"
	KindUnsupported ErrorKind = "unsupported"
	KindLimit       ErrorKind = "limit"
	KindDownload    ErrorKind = "download"
	KindExtract     ErrorKind = "extract"
)

// Error is a safe, classified archive-processing error.
type Error struct {
	Kind ErrorKind
	Op   string
	Err  error
}

func (e *Error) Error() string {
	if e.Op == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

func wrap(kind ErrorKind, op string, err error) error {
	if err == nil {
		return nil
	}
	var classified *Error
	if errors.As(err, &classified) {
		return err
	}
	return &Error{Kind: kind, Op: op, Err: err}
}

// KindOf returns the classification of err, or the empty string for an
// unclassified error.
func KindOf(err error) ErrorKind {
	var classified *Error
	if errors.As(err, &classified) {
		return classified.Kind
	}
	return ""
}
