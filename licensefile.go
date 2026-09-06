package licencly

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The signed license file format. This is a standalone copy of the format
// logic, not an import: pulling in a licensing SDK should give you one package,
// not a dependency tree. All four SDKs carry their own, and
// conformance/vectors.json is what keeps them in agreement.
//
// Format: lcl1.<base64url(payload)>.<base64url(signature)>
//
// The signature covers the ASCII of "lcl1.<payload>": the bytes exactly as
// transmitted. That removes any need for canonical JSON: two parsers that
// disagree about key ordering would otherwise compute different digests and
// reject each other's valid files.

const (
	// Prefix is the format version, and is part of the signed bytes, so a
	// future format cannot be relabelled as this one.
	Prefix = "lcl1"

	// FormatVersion is the license file schema version, distinct from the SDK's
	// own Version.
	FormatVersion = 1
)

// License statuses carried in the file.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusRevoked   = "revoked"
	StatusExpired   = "expired"
)

var (
	ErrMalformed      = errors.New("licencly: license file is malformed")
	ErrUnknownVersion = errors.New("licencly: unsupported license file version")
	ErrBadSignature   = errors.New("licencly: signature does not verify")
	ErrUnknownKey     = errors.New("licencly: license was signed by a key this build does not trust")
	ErrNotActive      = errors.New("licencly: license is not active")
	ErrExpired        = errors.New("licencly: license has expired")
	ErrWrongMachine   = errors.New("licencly: license was issued to a different machine")
	ErrStale          = errors.New("licencly: license is past its offline grace period")
)

// Claims is the verified content of a license file.
type Claims struct {
	Version     int    `json:"v"`
	KeyID       string `json:"kid"`
	LicenseUUID string `json:"lic"`
	Key         string `json:"key"`
	ProductUUID string `json:"prd"`
	CustomerRef string `json:"sub"`
	Status      string `json:"st"`
	Seats       int    `json:"seats"`
	Used        int    `json:"used"`
	Fingerprint string `json:"fp"`

	IssuedAt             int64 `json:"iat"`
	ExpiresAt            int64 `json:"exp"`
	MaintenanceExpiresAt int64 `json:"mnt"`
	RevalidateAfter      int64 `json:"rev"`
	GraceSeconds         int64 `json:"grace"`

	Metadata map[string]any `json:"meta,omitempty"`
}

var enc = base64.RawURLEncoding

// Decode parses the payload WITHOUT verifying the signature.
//
// Its only legitimate use is reading KeyID to choose a public key. Every claim
// is attacker-controlled until Verify has succeeded.
func Decode(token string) (Claims, error) {
	_, claims, _, err := split(token)
	return claims, err
}

// Verify checks the signature. It does not evaluate expiry, status or machine
// binding: call Claims.Check for that, so a caller can tell "forged" apart
// from "expired".
func Verify(token string, pub ed25519.PublicKey) (Claims, error) {
	signed, claims, sig, err := split(token)
	if err != nil {
		return Claims{}, err
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, signed, sig) {
		return Claims{}, ErrBadSignature
	}
	return claims, nil
}

// VerifyWithKeys selects the public key by the file's key id.
//
// An unknown id is refused rather than retried against every key held: a client
// that tries them all accepts a file signed by a rotated-out key an attacker
// recovered.
func VerifyWithKeys(token string, keys map[string]ed25519.PublicKey) (Claims, error) {
	unverified, err := Decode(token)
	if err != nil {
		return Claims{}, err
	}

	pub, ok := keys[unverified.KeyID]
	if !ok {
		return Claims{}, fmt.Errorf("%w (key id %q)", ErrUnknownKey, unverified.KeyID)
	}
	return Verify(token, pub)
}

func split(token string) (signed []byte, claims Claims, sig []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, Claims{}, nil, ErrMalformed
	}
	if parts[0] != Prefix {
		return nil, Claims{}, nil, ErrUnknownVersion
	}

	payload, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, Claims{}, nil, ErrMalformed
	}
	sig, err = enc.DecodeString(parts[2])
	if err != nil {
		return nil, Claims{}, nil, ErrMalformed
	}

	if err := json.NewDecoder(bytes.NewReader(payload)).Decode(&claims); err != nil {
		return nil, Claims{}, nil, ErrMalformed
	}
	if claims.Version != FormatVersion {
		return nil, Claims{}, nil, ErrUnknownVersion
	}
	return []byte(parts[0] + "." + parts[1]), claims, sig, nil
}

// Check evaluates verified claims against the local clock and machine.
//
// fingerprint may be empty when the platform cannot produce one, in which case
// the machine binding is skipped, but a file issued to a specific machine will
// then be accepted anywhere, so pass one whenever you can.
func (c Claims) Check(now time.Time, fingerprint string) error {
	if c.Status != StatusActive {
		return fmt.Errorf("%w: %s", ErrNotActive, c.Status)
	}
	if c.ExpiresAt != 0 && now.Unix() > c.ExpiresAt {
		return ErrExpired
	}
	if c.Fingerprint != "" && fingerprint != "" && c.Fingerprint != fingerprint {
		return ErrWrongMachine
	}
	if c.RevalidateAfter != 0 && now.Unix() > c.RevalidateAfter+c.GraceSeconds {
		return ErrStale
	}
	return nil
}

// NeedsRevalidation reports whether the file is past its check-in time but
// still inside the grace window: the period where the app keeps running and
// refreshes in the background.
func (c Claims) NeedsRevalidation(now time.Time) bool {
	return c.RevalidateAfter != 0 && now.Unix() > c.RevalidateAfter
}

// MaintenanceActive reports entitlement to releases published now. A perpetual
// license with lapsed maintenance keeps running but stops receiving updates.
func (c Claims) MaintenanceActive(now time.Time) bool {
	return c.MaintenanceExpiresAt == 0 || now.Unix() <= c.MaintenanceExpiresAt
}

// ExpiresAtTime returns the expiry, or the zero time for a perpetual license.
func (c Claims) ExpiresAtTime() time.Time {
	if c.ExpiresAt == 0 {
		return time.Time{}
	}
	return time.Unix(c.ExpiresAt, 0).UTC()
}
