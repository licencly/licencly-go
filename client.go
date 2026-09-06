// Package licencly verifies Licencly licenses and checks for entitled updates.
//
// The design in one sentence: the signed license file is the answer, and the
// network is an optimisation. Validate reads the cache, refreshes when due, and
// keeps working through an outage until the grace period is spent, so Licencly
// being unreachable never stops software you have already sold.
//
//	client, err := licencly.New(licencly.Config{
//	    ProductUUID: "…",
//	    PublicKeys:  licencly.MustParseKeys(map[string]string{"<kid>": "<base64>"}),
//	})
//
//	decision, err := client.Validate(ctx, licenseKey)
//	if !decision.OK() {
//	    // decision.Outcome says why
//	}
package licencly

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Version of this SDK, sent in the user agent so a vendor's traffic is
// identifiable when they ask for support.
const Version = "1.0.0"

const (
	defaultBaseURL = "https://licencly.com"
	defaultTimeout = 10 * time.Second
	// Artifacts are installers, routinely hundreds of megabytes, and
	// http.Client.Timeout covers the body read as well as the request. Reusing
	// the API timeout here aborts every download that takes longer than ten
	// seconds, which is most of them.
	defaultDownloadTimeout = 30 * time.Minute
	defaultRetries         = 2
)

// clockSkewTolerance is how far the clock may move backwards before it is
// treated as tampering rather than an NTP correction or a timezone change.
const clockSkewTolerance = 24 * time.Hour

type Config struct {
	// ProductUUID identifies your product. From the dashboard.
	ProductUUID string

	// PublicKeys maps a signing key id to its public key. Embed these in your
	// application at build time: fetching them at runtime would defeat the
	// entire scheme.
	//
	// Include retired keys as well as the active one: a license signed before
	// a rotation still verifies against the key it was signed with.
	PublicKeys map[string]ed25519.PublicKey

	// Fingerprint identifies this machine. Empty disables machine binding,
	// which makes the file usable anywhere it is copied.
	Fingerprint string

	// Cache persists the last good file. Defaults to a per-user file.
	Cache Cache

	BaseURL    string
	HTTPClient *http.Client
	Timeout    time.Duration
	// DownloadTimeout bounds an artifact download, which is a different order
	// of magnitude from an API call. Defaults to 30 minutes. Pass a context
	// with a deadline for finer control.
	DownloadTimeout time.Duration
	Retries         int

	// Hostname, Platform and AppVersion are reported on activation so a vendor
	// can recognise machines in their dashboard. Optional.
	Hostname   string
	Platform   string
	AppVersion string

	// Now overrides the clock, for tests.
	Now func() time.Time
}

type Client struct {
	cfg  Config
	http *http.Client
	// download is separate only for its timeout; it shares the transport, so a
	// caller's proxy and dialer settings still apply. A caller who supplied
	// their own HTTPClient gets that one for both, timeout included.
	download *http.Client
}

func New(cfg Config) (*Client, error) {
	if cfg.ProductUUID == "" {
		return nil, fmt.Errorf("licencly: ProductUUID is required")
	}
	if len(cfg.PublicKeys) == 0 {
		return nil, fmt.Errorf("licencly: at least one public key is required, or nothing can be verified")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	if cfg.DownloadTimeout == 0 {
		cfg.DownloadTimeout = defaultDownloadTimeout
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Retries == 0 {
		cfg.Retries = defaultRetries
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.Cache == nil {
		path, err := DefaultCachePath(cfg.ProductUUID)
		if err != nil {
			// Falling back to memory rather than failing: an unusual home
			// directory should degrade the offline story, not break startup.
			cfg.Cache = &MemoryCache{}
		} else {
			cfg.Cache = &FileCache{Path: path}
		}
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	download := client
	if cfg.HTTPClient == nil {
		download = &http.Client{Timeout: cfg.DownloadTimeout, Transport: client.Transport}
	}
	return &Client{cfg: cfg, http: client, download: download}, nil
}

// Validate decides whether this machine may run.
//
// It refreshes from the server when the cached file is due, and falls back to
// the cache whenever the server cannot be reached, so a Licencly outage does
// not stop software that has already been sold. It never blocks on the network
// while a usable cached file exists.
//
// The cache is keyed on the product, so it can hold a license other than the
// one being validated. A cached file is only reused when its key claim matches
// the key asked about and its fingerprint matches this machine; otherwise the
// server is asked, because answering with a different customer's license would
// be worse than failing.
func (c *Client) Validate(ctx context.Context, licenseKey string) (Decision, error) {
	now := c.cfg.Now()
	cached, highestSeen, _ := c.cfg.Cache.Load()

	// A large jump backwards from the furthest time seen is not an NTP
	// correction. A speed bump rather than a fix: anyone who can set the clock
	// can also patch the binary.
	if !highestSeen.IsZero() && now.Add(clockSkewTolerance).Before(highestSeen) {
		return Decision{
			Outcome: OutcomeInvalid,
			Err:     fmt.Errorf("licencly: system clock moved backwards by more than %s", clockSkewTolerance),
		}, nil
	}

	cacheAnswersThisKey := false
	if cached != "" {
		if claims, err := VerifyWithKeys(cached, c.cfg.PublicKeys); err == nil {
			// An absent key claim cannot be compared, so it counts as a match:
			// every file the server issues carries one.
			cacheAnswersThisKey = claims.Key == "" ||
				foldKey(claims.Key) == foldKey(licenseKey)

			sameMachine := claims.Fingerprint == "" || c.cfg.Fingerprint == "" ||
				claims.Fingerprint == c.cfg.Fingerprint

			if cacheAnswersThisKey && sameMachine && !claims.NeedsRevalidation(now) {
				return evaluate(claims, nil, now, c.cfg.Fingerprint, true), nil
			}
		}
	}

	file, err := c.fetch(ctx, licenseKey)
	if err != nil {
		if cached == "" || !cacheAnswersThisKey {
			// Stale rather than invalid: the caller is offline, not holding a
			// forged file, and invalid tells an application to accuse its user
			// of tampering.
			outcome := OutcomeInvalid
			if IsNetwork(err) {
				outcome = OutcomeStale
			}
			return Decision{Outcome: outcome, Err: err}, err
		}

		claims, verifyErr := VerifyWithKeys(cached, c.cfg.PublicKeys)
		return evaluate(claims, verifyErr, now, c.cfg.Fingerprint, true), nil
	}

	claims, verifyErr := VerifyWithKeys(file, c.cfg.PublicKeys)
	if verifyErr == nil {
		seen := highestSeen
		if now.After(seen) {
			seen = now
		}
		_ = c.cfg.Cache.Save(file, seen)
	}
	return evaluate(claims, verifyErr, now, c.cfg.Fingerprint, false), nil
}

// Deactivate frees this machine's seat.
func (c *Client) Deactivate(ctx context.Context, licenseKey string) error {
	body, _ := json.Marshal(map[string]string{
		"product":     c.cfg.ProductUUID,
		"key":         licenseKey,
		"fingerprint": c.cfg.Fingerprint,
	})

	_, err := c.do(ctx, http.MethodPost, "/v1/licenses/deactivate", bytes.NewReader(body))
	if err != nil {
		return err
	}
	return c.cfg.Cache.Clear()
}

// ClearCache removes the stored license. Exposed so support can say "run this".
func (c *Client) ClearCache() error { return c.cfg.Cache.Clear() }

type validateResponse struct {
	License string `json:"license"`
	Status  string `json:"status"`
	Seats   int    `json:"seats"`
	Used    int    `json:"used"`
}

func (c *Client) fetch(ctx context.Context, licenseKey string) (string, error) {
	payload := map[string]string{
		"product": c.cfg.ProductUUID,
		"key":     licenseKey,
	}
	if c.cfg.Fingerprint != "" {
		payload["fingerprint"] = c.cfg.Fingerprint
		payload["hostname"] = c.cfg.Hostname
		payload["platform"] = c.cfg.Platform
		payload["app_version"] = c.cfg.AppVersion
	}
	body, _ := json.Marshal(payload)

	raw, err := c.do(ctx, http.MethodPost, "/v1/licenses/validate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	var res validateResponse
	if err := json.Unmarshal(raw, &res); err != nil {
		return "", fmt.Errorf("licencly: could not parse the response: %w", err)
	}
	if res.License == "" {
		return "", fmt.Errorf("licencly: the server returned no license file")
	}
	return res.License, nil
}

// MustParseKeys turns base64 public keys into the map Config wants. It panics
// on malformed input, which is correct for keys compiled into a binary: a bad
// key is a build error, not a runtime condition.
func MustParseKeys(keys map[string]string) map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(keys))
	for kid, encoded := range keys {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			panic("licencly: public key for " + kid + " is not valid base64: " + err.Error())
		}
		if len(raw) != ed25519.PublicKeySize {
			panic("licencly: public key for " + kid + " is " +
				strconv.Itoa(len(raw)) + " bytes, want " + strconv.Itoa(ed25519.PublicKeySize))
		}
		out[kid] = ed25519.PublicKey(raw)
	}
	return out
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader) ([]byte, error) {
	var payload []byte
	if body != nil {
		payload, _ = io.ReadAll(body)
	}

	var lastErr error
	for attempt := 0; attempt <= c.cfg.Retries; attempt++ {
		if attempt > 0 {
			// Exponential backoff. Validate is idempotent, so retrying is safe.
			delay := time.Duration(1<<uint(attempt-1)) * 200 * time.Millisecond
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, &NetworkError{Err: ctx.Err()}
			}
		}

		req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "licencly-go/"+Version)

		res, err := c.http.Do(req)
		if err != nil {
			lastErr = &NetworkError{Err: err}
			continue
		}

		raw, readErr := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		if readErr != nil {
			lastErr = &NetworkError{Err: readErr}
			continue
		}

		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return raw, nil
		}

		apiErr := parseAPIError(res, raw)
		// 4xx is a decision, not a hiccup: retrying an invalid key just makes
		// the same answer arrive three times.
		if res.StatusCode < 500 {
			return nil, apiErr
		}
		lastErr = apiErr
	}
	return nil, lastErr
}

func parseAPIError(res *http.Response, raw []byte) *APIError {
	out := &APIError{
		Status:  res.StatusCode,
		Code:    "unexpected_error",
		Message: fmt.Sprintf("request failed (%d)", res.StatusCode),
	}

	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err == nil && envelope.Error.Code != "" {
		out.Code, out.Message = envelope.Error.Code, envelope.Error.Message
	}
	if v := res.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			out.RetryAfter = time.Duration(secs) * time.Second
		}
	}
	return out
}

// foldKey folds a license key the way the server does, for comparison only.
//
// Mirrors NormalizeKey server side: upper case, drop the grouping characters,
// and map the look-alikes Crockford base32 leaves out. No checksum here; this
// only ever compares two values, and rejecting a key is the server's job.
func foldKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range strings.ToUpper(strings.TrimSpace(key)) {
		switch {
		case r == '-' || r == ' ' || r == '\t' || r == '_':
			continue
		case r == 'I' || r == 'L':
			b.WriteByte('1')
		case r == 'O':
			b.WriteByte('0')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
