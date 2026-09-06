package licencly

import (
	"errors"
	"time"
)

// Outcome is the result of evaluating a license. The set is fixed and shared by
// every Licencly SDK.
type Outcome string

const (
	// OutcomeValid means verified and inside its window. Run.
	OutcomeValid Outcome = "valid"
	// OutcomeInvalid means the signature or format failed. This is tampering,
	// not a network problem: refuse, and do not retry.
	OutcomeInvalid Outcome = "invalid"
	// OutcomeNotActive means suspended, revoked or expired by status.
	OutcomeNotActive Outcome = "not_active"
	// OutcomeExpired means past its expiry date.
	OutcomeExpired Outcome = "expired"
	// OutcomeWrongMachine means the file was issued to a different machine.
	OutcomeWrongMachine Outcome = "wrong_machine"
	// OutcomeStale means the offline grace period is spent and the server
	// could not be reached.
	OutcomeStale Outcome = "stale"
)

// Decision is what an application acts on.
type Decision struct {
	Outcome Outcome
	// Claims is populated whenever the signature verified, even if the license
	// is expired or revoked, so an app can say *which* license expired.
	Claims Claims
	// NeedsRevalidation is true inside the grace window: keep running, refresh
	// in the background.
	NeedsRevalidation bool
	// FromCache reports that no network call was made or that one failed and
	// the cached file was used.
	FromCache bool
	// Err carries the underlying cause for anything other than valid.
	Err error
}

// OK is the single check an application should gate on.
func (d Decision) OK() bool { return d.Outcome == OutcomeValid }

// MaintenanceActive reports entitlement to new releases.
func (d Decision) MaintenanceActive(now time.Time) bool {
	return d.Claims.MaintenanceActive(now)
}

// evaluate maps a verification result onto an Outcome. Kept in one place so the
// mapping cannot drift between the cached and freshly-fetched paths.
func evaluate(claims Claims, err error, now time.Time, fingerprint string, fromCache bool) Decision {
	if err != nil {
		return Decision{Outcome: OutcomeInvalid, Err: err, FromCache: fromCache}
	}

	d := Decision{
		Claims:            claims,
		NeedsRevalidation: claims.NeedsRevalidation(now),
		FromCache:         fromCache,
	}

	switch err := claims.Check(now, fingerprint); {
	case err == nil:
		d.Outcome = OutcomeValid
	case errors.Is(err, ErrWrongMachine):
		d.Outcome, d.Err = OutcomeWrongMachine, err
	case errors.Is(err, ErrNotActive):
		d.Outcome, d.Err = OutcomeNotActive, err
	case errors.Is(err, ErrExpired):
		d.Outcome, d.Err = OutcomeExpired, err
	case errors.Is(err, ErrStale):
		d.Outcome, d.Err = OutcomeStale, err
	default:
		d.Outcome, d.Err = OutcomeInvalid, err
	}
	return d
}
