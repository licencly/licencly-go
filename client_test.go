package licencly

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

const testKID = "test-key-1"

type fixture struct {
	server   *httptest.Server
	client   *Client
	cache    *MemoryCache
	calls    *int32
	sign     func(Claims) string
	now      time.Time
	failWith int
}

// newFixture wires a client against a fake server that returns whatever license
// file the test asks for.
func newFixture(t *testing.T, claims func() Claims) *fixture {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	f := &fixture{
		cache: &MemoryCache{},
		calls: new(int32),
		now:   time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
	}

	f.sign = func(c Claims) string {
		c.Version = FormatVersion
		c.KeyID = testKID
		payload, _ := json.Marshal(c)
		signed := Prefix + "." + enc.EncodeToString(payload)
		return signed + "." + enc.EncodeToString(ed25519.Sign(priv, []byte(signed)))
	}

	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(f.calls, 1)

		if f.failWith != 0 {
			w.WriteHeader(f.failWith)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]string{"code": "seat_limit_reached", "message": "no free seats"},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(validateResponse{License: f.sign(claims()), Status: "active"})
	}))
	t.Cleanup(f.server.Close)

	client, err := New(Config{
		ProductUUID: "product-uuid",
		PublicKeys:  map[string]ed25519.PublicKey{testKID: pub},
		Fingerprint: "machine-abc",
		Cache:       f.cache,
		BaseURL:     f.server.URL,
		Retries:     0,
		Now:         func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	f.client = client
	return f
}

func activeClaims(now time.Time) Claims {
	return Claims{
		LicenseUUID: "license-uuid",
		// Every file the server issues names the license it is for, and the
		// client now checks it: a cache keyed on the product alone would
		// otherwise answer for whichever license was validated last.
		Key:             "KEY",
		ProductUUID:     "product-uuid",
		Status:          StatusActive,
		Seats:           5,
		Used:            1,
		Fingerprint:     "machine-abc",
		IssuedAt:        now.Add(-time.Hour).Unix(),
		RevalidateAfter: now.Add(7 * 24 * time.Hour).Unix(),
		GraceSeconds:    int64((7 * 24 * time.Hour).Seconds()),
	}
}

func TestValidateFetchesThenServesFromCache(t *testing.T) {
	f := newFixture(t, func() Claims { return activeClaims(f0(t)) })
	ctx := context.Background()

	d, err := f.client.Validate(ctx, "KEY")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !d.OK() {
		t.Fatalf("outcome %q", d.Outcome)
	}
	if d.FromCache {
		t.Fatal("first call should have hit the network")
	}
	if got := atomic.LoadInt32(f.calls); got != 1 {
		t.Fatalf("%d calls, want 1", got)
	}

	// Second call is inside the revalidation window, so it must not touch the
	// network at all. An app that phones home on every launch is an app that
	// fails to launch on a plane.
	d, err = f.client.Validate(ctx, "KEY")
	if err != nil {
		t.Fatalf("second validate: %v", err)
	}
	if !d.OK() || !d.FromCache {
		t.Fatalf("outcome %q fromCache %v", d.Outcome, d.FromCache)
	}
	if got := atomic.LoadInt32(f.calls); got != 1 {
		t.Fatalf("%d calls, want still 1", got)
	}
}

// The behaviour the product is sold on: Licencly is unreachable, and software
// already paid for keeps working.
func TestServerDownInsideGraceKeepsWorking(t *testing.T) {
	f := newFixture(t, func() Claims { return activeClaims(f0(t)) })
	ctx := context.Background()

	if _, err := f.client.Validate(ctx, "KEY"); err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	f.server.Close()

	// Past the check-in time, inside grace.
	f.now = f.now.Add(8 * 24 * time.Hour)

	d, err := f.client.Validate(ctx, "KEY")
	if err != nil {
		t.Fatalf("validate with the server down: %v", err)
	}
	if !d.OK() {
		t.Fatalf("outcome %q: an outage must not stop a paid license", d.Outcome)
	}
	if !d.FromCache {
		t.Fatal("expected the cached file")
	}
	if !d.NeedsRevalidation {
		t.Fatal("needs_revalidation should be true past the check-in time")
	}
}

func TestPastGraceIsStale(t *testing.T) {
	f := newFixture(t, func() Claims { return activeClaims(f0(t)) })
	ctx := context.Background()

	if _, err := f.client.Validate(ctx, "KEY"); err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	f.server.Close()

	// Past rev + grace: the offline allowance is spent.
	f.now = f.now.Add(20 * 24 * time.Hour)

	d, err := f.client.Validate(ctx, "KEY")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if d.Outcome != OutcomeStale {
		t.Fatalf("outcome %q, want stale", d.Outcome)
	}
}

func TestRevokedLicenseTakesEffectOnRefresh(t *testing.T) {
	status := StatusActive
	f := newFixture(t, func() Claims {
		c := activeClaims(f0(t))
		c.Status = status
		return c
	})
	ctx := context.Background()

	if d, _ := f.client.Validate(ctx, "KEY"); !d.OK() {
		t.Fatalf("outcome %q", d.Outcome)
	}

	status = StatusRevoked
	f.now = f.now.Add(8 * 24 * time.Hour) // due for a check-in

	d, err := f.client.Validate(ctx, "KEY")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if d.Outcome != OutcomeNotActive {
		t.Fatalf("outcome %q, want not_active", d.Outcome)
	}
}

// Caching a file we could not verify would poison every later offline launch.
func TestUnverifiableResponseIsNotCached(t *testing.T) {
	f := newFixture(t, func() Claims { return activeClaims(f0(t)) })
	ctx := context.Background()

	// Swap the server for one returning a file signed by a key we do not hold.
	otherPub, otherPriv, _ := ed25519.GenerateKey(nil)
	_ = otherPub
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := activeClaims(f0(t))
		c.Version, c.KeyID = FormatVersion, testKID
		payload, _ := json.Marshal(c)
		signed := Prefix + "." + enc.EncodeToString(payload)
		token := signed + "." + enc.EncodeToString(ed25519.Sign(otherPriv, []byte(signed)))
		_ = json.NewEncoder(w).Encode(validateResponse{License: token})
	})

	d, err := f.client.Validate(ctx, "KEY")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if d.Outcome != OutcomeInvalid {
		t.Fatalf("outcome %q, want invalid", d.Outcome)
	}

	cached, _, _ := f.cache.Load()
	if cached != "" {
		t.Fatal("an unverifiable file was written to the cache")
	}
}

// Rolling the clock back is not a fix, but it should not be free either.
func TestClockRolledBackIsRejected(t *testing.T) {
	f := newFixture(t, func() Claims { return activeClaims(f0(t)) })
	ctx := context.Background()

	if _, err := f.client.Validate(ctx, "KEY"); err != nil {
		t.Fatalf("prime cache: %v", err)
	}

	f.now = f.now.Add(-90 * 24 * time.Hour)

	d, err := f.client.Validate(ctx, "KEY")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if d.Outcome != OutcomeInvalid {
		t.Fatalf("outcome %q, want invalid after a large backward clock jump", d.Outcome)
	}
}

func TestAPIErrorsAreDistinguishable(t *testing.T) {
	f := newFixture(t, func() Claims { return activeClaims(f0(t)) })
	f.failWith = http.StatusConflict

	_, err := f.client.Validate(context.Background(), "KEY")
	if err == nil {
		t.Fatal("expected an error with no cache and a refusing server")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("got %T, want *APIError", err)
	}
	if !apiErr.SeatLimitReached() {
		t.Fatalf("code %q: a caller cannot tell the user to free a seat", apiErr.Code)
	}
	if IsNetwork(err) {
		t.Fatal("a 409 reported as a network error")
	}
}

func TestNetworkFailureWithNoCacheIsRetryable(t *testing.T) {
	f := newFixture(t, func() Claims { return activeClaims(f0(t)) })
	f.server.Close()

	_, err := f.client.Validate(context.Background(), "KEY")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !IsNetwork(err) {
		t.Fatalf("got %v, want a NetworkError so the caller knows to retry", err)
	}
}

func TestNewRejectsAConfigThatCannotVerify(t *testing.T) {
	if _, err := New(Config{ProductUUID: "p"}); err == nil {
		t.Fatal("a client with no public keys cannot verify anything and must not be constructed")
	}
	if _, err := New(Config{PublicKeys: map[string]ed25519.PublicKey{"k": make([]byte, 32)}}); err == nil {
		t.Fatal("a client with no product uuid must not be constructed")
	}
}

func TestMustParseKeysRejectsBadInput(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a malformed embedded key is a build error and must panic")
		}
	}()
	MustParseKeys(map[string]string{"k": "not base64!!"})
}

// f0 is the fixed instant the fixtures are built around.
func f0(t *testing.T) time.Time {
	t.Helper()
	return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
}

var _ = base64.StdEncoding

// The cache is keyed on the product, so it holds the previous license.
// Validating a different key must not answer with the old one: a customer
// upgrading from a trial to a paid key, or replacing a revoked key, would
// otherwise keep being told about the license they just stopped using.
func TestValidateDoesNotReuseAnotherLicensesCache(t *testing.T) {
	f := newFixture(t, func() Claims { return activeClaims(f0(t)) })
	ctx := context.Background()

	if _, err := f.client.Validate(ctx, "KEY"); err != nil {
		t.Fatalf("first validate: %v", err)
	}
	if got := atomic.LoadInt32(f.calls); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}

	// Same product, different key. The cached file is fresh, so the old
	// behaviour returned it without a single network call.
	d, err := f.client.Validate(ctx, "OTHER-KEY")
	if err != nil {
		t.Fatalf("second validate: %v", err)
	}
	if got := atomic.LoadInt32(f.calls); got != 2 {
		t.Errorf("calls = %d, want 2: a different license must reach the server", got)
	}
	if d.FromCache {
		t.Error("FromCache = true, want false for a different license")
	}
}

func TestValidateOfflineWithAnotherLicensesCacheFails(t *testing.T) {
	f := newFixture(t, func() Claims { return activeClaims(f0(t)) })
	ctx := context.Background()

	if _, err := f.client.Validate(ctx, "KEY"); err != nil {
		t.Fatalf("first validate: %v", err)
	}
	f.server.Close()

	// Falling back to the cache would report the wrong customer, the wrong
	// expiry and the wrong seat count. Failing is the lesser evil.
	if _, err := f.client.Validate(ctx, "OTHER-KEY"); err == nil {
		t.Fatal("want an error when offline with only another license cached")
	}
}

// A first run with no network must not report tampering. The application is
// told to show "the file did not verify" for OutcomeInvalid, and saying that to
// someone who is merely offline is both wrong and alarming.
func TestValidateOfflineFirstRunIsStaleNotInvalid(t *testing.T) {
	f := newFixture(t, func() Claims { return activeClaims(f0(t)) })
	f.server.Close() // nothing was ever cached, and now nothing answers

	d, err := f.client.Validate(context.Background(), "KEY")
	if err == nil {
		t.Fatal("want an error when the server cannot be reached on a first run")
	}
	if !IsNetwork(err) {
		t.Fatalf("err = %v, want a network error", err)
	}
	if d.Outcome != OutcomeStale {
		t.Errorf("Outcome = %q, want %q: invalid means tampering", d.Outcome, OutcomeStale)
	}
}
