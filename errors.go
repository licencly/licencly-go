package licencly

import (
	"errors"
	"fmt"
	"time"
)

// Errors a caller has to tell apart. Collapsing these into one type is the most
// common way to make a licensing integration unsupportable: "it doesn't work"
// means something different for each.

// NetworkError means Licencly could not be reached. Retryable, and inside the
// grace window it is not something the user should be shown.
type NetworkError struct{ Err error }

func (e *NetworkError) Error() string {
	return "licencly: could not reach the server: " + e.Err.Error()
}
func (e *NetworkError) Unwrap() error { return e.Err }

// APIError is a structured refusal from the server.
type APIError struct {
	Status  int
	Code    string
	Message string
	// RetryAfter is set on a 429.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("licencly: %s (%s)", e.Message, e.Code)
}

// NotFound reports an unknown product, an unknown key, or a malformed one. The
// server deliberately does not distinguish them: that would let anyone probe
// which keys are real.
func (e *APIError) NotFound() bool { return e.Status == 404 }

// SeatLimitReached reports that the license is in use on the maximum number of
// machines. Distinguished from NotFound because the holder has proved they own
// a real key and needs to be told to free a seat.
func (e *APIError) SeatLimitReached() bool { return e.Code == "seat_limit_reached" }

func (e *APIError) RateLimited() bool { return e.Status == 429 }

// IsNetwork reports whether the failure was reaching the server rather than
// anything about the license. Inside the grace period this should be handled
// silently.
func IsNetwork(err error) bool {
	var n *NetworkError
	return errors.As(err, &n)
}

// IsTampering reports whether the license file failed verification. Never retry
// these: retrying obscures an attack and fixes nothing.
func IsTampering(err error) bool {
	return errors.Is(err, ErrBadSignature) ||
		errors.Is(err, ErrMalformed) ||
		errors.Is(err, ErrUnknownKey) ||
		errors.Is(err, ErrUnknownVersion)
}
