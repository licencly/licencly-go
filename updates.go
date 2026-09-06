package licencly

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

// UpdateOutcome mirrors the server's vocabulary exactly, so a vendor reading
// their logs sees the same word the API returned.
type UpdateOutcome string

const (
	UpdateAvailable UpdateOutcome = "update_available"
	UpToDate        UpdateOutcome = "up_to_date"
	// MaintenanceLapsed is NOT an error. A newer release exists and this
	// license is not entitled to it; Latest names what a renewal would unlock.
	MaintenanceLapsed UpdateOutcome = "maintenance_lapsed"
	// UpgradeBlocked means an entitled release exists but needs an
	// intermediate version this client has not reached.
	UpgradeBlocked UpdateOutcome = "upgrade_blocked"
	NotEntitled    UpdateOutcome = "not_entitled"
)

type Release struct {
	UUID             string `json:"uuid"`
	Version          string `json:"version"`
	Channel          string `json:"channel"`
	Platform         string `json:"platform"`
	Arch             string `json:"arch"`
	Notes            string `json:"notes"`
	MinUpgradeFrom   string `json:"min_upgrade_from"`
	ArtifactSize     int64  `json:"artifact_size"`
	ArtifactSHA256   string `json:"artifact_sha256"`
	ArtifactFilename string `json:"artifact_filename"`
	Signed           bool   `json:"signed"`
}

type UpdateResult struct {
	Outcome UpdateOutcome
	// Release is the one to install, when Outcome is UpdateAvailable.
	Release *Release
	// Latest is what a renewal would unlock, when held back.
	Latest      *Release
	DownloadURL string
}

// Available is the single check for "should I offer an update".
func (r UpdateResult) Available() bool { return r.Outcome == UpdateAvailable }

// RenewalWouldUnlock reports that a newer release exists but this license
// cannot have it: a prompt, not a failure.
func (r UpdateResult) RenewalWouldUnlock() bool {
	return r.Outcome == MaintenanceLapsed && r.Latest != nil
}

type UpdateQuery struct {
	CurrentVersion string
	Channel        string
	Platform       string
	Arch           string
}

// CheckForUpdate asks which release this license is entitled to.
//
// Never consumes a seat: a background updater polling weekly must not exhaust a
// customer's activations.
func (c *Client) CheckForUpdate(ctx context.Context, licenseKey string, q UpdateQuery) (UpdateResult, error) {
	params := url.Values{}
	params.Set("key", licenseKey)
	if q.CurrentVersion != "" {
		params.Set("version", q.CurrentVersion)
	}
	for key, value := range map[string]string{
		"channel": q.Channel, "platform": q.Platform, "arch": q.Arch,
	} {
		if value != "" {
			params.Set(key, value)
		}
	}

	path := "/v1/products/" + url.PathEscape(c.cfg.ProductUUID) + "/updates/check?" + params.Encode()

	raw, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return UpdateResult{}, err
	}

	var res struct {
		Outcome     string   `json:"outcome"`
		Release     *Release `json:"release"`
		Latest      *Release `json:"latest"`
		DownloadURL string   `json:"download_url"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return UpdateResult{}, fmt.Errorf("licencly: could not parse the update response: %w", err)
	}

	return UpdateResult{
		Outcome:     UpdateOutcome(res.Outcome),
		Release:     res.Release,
		Latest:      res.Latest,
		DownloadURL: res.DownloadURL,
	}, nil
}

var (
	ErrChecksumMismatch  = errors.New("licencly: downloaded artifact does not match its checksum")
	ErrArtifactSignature = errors.New("licencly: artifact signature does not verify against your artifact key")
	ErrArtifactUnsigned  = errors.New("licencly: artifact carries no signature")
)

// DownloadArtifact fetches a release and verifies it before returning a path.
//
// artifactKey is YOUR Ed25519 public key, compiled into this application and
// not fetched from Licencly. That is what makes the guarantee real: Licencly
// stores and serves the signature but cannot produce one, so a compromise of
// Licencly cannot push code to your users.
//
// Passing a nil key skips signature verification and only checks the digest.
// Do that only if you have not set up artifact signing; it reduces the check to
// corruption detection.
//
// artifactKey comes last to match the Node, Python and .NET SDKs, where it is
// the optional argument and so has to. Four SDKs that disagree on argument
// order is a trap for anyone porting an integration between them.
func (c *Client) DownloadArtifact(
	ctx context.Context,
	licenseKey string,
	release *Release,
	destDir string,
	artifactKey ed25519.PublicKey,
) (string, error) {
	if release == nil {
		return "", fmt.Errorf("licencly: no release given")
	}

	path := fmt.Sprintf("/v1/products/%s/releases/%s/download?key=%s",
		url.PathEscape(c.cfg.ProductUUID), url.PathEscape(release.UUID), url.QueryEscape(licenseKey))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "licencly-go/"+Version)

	res, err := c.download.Do(req)
	if err != nil {
		return "", &NetworkError{Err: err}
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
		return "", parseAPIError(res, raw)
	}

	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return "", err
	}

	// Base first: the filename comes from the server, and a path in it must not
	// be able to place a file outside destDir.
	// Base first: the filename comes from the server, and a path in it must not
	// be able to place a file outside destDir.
	name := filepath.Base(release.ArtifactFilename)
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "artifact.bin"
	}

	// Download to a temporary name and rename only after verification, so a
	// half-written or unverified artifact is never left where something might
	// execute it.
	tmp := filepath.Join(destDir, "."+name+".partial")
	final := filepath.Join(destDir, name)

	file, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp)

	digest := sha256.New()

	if _, err := io.Copy(io.MultiWriter(file, digest), res.Body); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}

	if got := hex.EncodeToString(digest.Sum(nil)); got != release.ArtifactSHA256 {
		return "", fmt.Errorf("%w: got %s, expected %s", ErrChecksumMismatch, got, release.ArtifactSHA256)
	}

	if artifactKey != nil {
		encoded := res.Header.Get("X-Artifact-Signature")
		if encoded == "" {
			return "", ErrArtifactUnsigned
		}
		sig, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", fmt.Errorf("%w: signature is not valid base64", ErrArtifactSignature)
		}

		// Re-read from disk rather than trusting anything held in memory, so
		// what is verified is exactly what will be executed.
		contents, err := os.ReadFile(tmp)
		if err != nil {
			return "", err
		}
		if !ed25519.Verify(artifactKey, contents, sig) {
			return "", ErrArtifactSignature
		}
	}

	if err := os.Rename(tmp, final); err != nil {
		return "", err
	}
	return final, nil
}
