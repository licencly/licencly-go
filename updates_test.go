package licencly

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The artifact path is what backs the claim that a compromise of Licencly
// cannot push code to a vendor's users. Every one of these checks a way that
// guarantee could be lost.

type artifactServer struct {
	body      []byte
	signature string
	status    int
}

func newArtifactClient(t *testing.T, s *artifactServer) *Client {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.status != 0 {
			w.WriteHeader(s.status)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]string{"code": "not_found", "message": "no such release"},
			})
			return
		}
		if s.signature != "" {
			w.Header().Set("X-Artifact-Signature", s.signature)
		}
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(srv.Close)

	c, err := New(Config{
		ProductUUID: "product-uuid",
		PublicKeys:  map[string]ed25519.PublicKey{"k": pub},
		Cache:       &MemoryCache{},
		BaseURL:     srv.URL,
		Retries:     0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestDownloadArtifactWritesAVerifiedFile(t *testing.T) {
	body := []byte("this is a release artifact")
	c := newArtifactClient(t, &artifactServer{body: body})
	dir := t.TempDir()

	path, err := c.DownloadArtifact(context.Background(), "KEY", &Release{
		UUID:             "rel-1",
		ArtifactSHA256:   digestOf(body),
		ArtifactFilename: "acme-cad-4.0.0.bin",
	}, dir, nil)
	if err != nil {
		t.Fatalf("DownloadArtifact: %v", err)
	}

	if filepath.Base(path) != "acme-cad-4.0.0.bin" {
		t.Errorf("path = %q", path)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Error("the written file does not match what was served")
	}
}

// A corrupted download must be refused, and must leave nothing behind that
// something else might pick up and run.
func TestDownloadArtifactRejectsAChecksumMismatch(t *testing.T) {
	c := newArtifactClient(t, &artifactServer{body: []byte("tampered bytes")})
	dir := t.TempDir()

	_, err := c.DownloadArtifact(context.Background(), "KEY", &Release{
		ArtifactSHA256:   digestOf([]byte("the bytes we expected")),
		ArtifactFilename: "app.bin",
	}, dir, nil)

	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("err = %v, want ErrChecksumMismatch", err)
	}
	assertDirEmpty(t, dir)
}

func TestDownloadArtifactVerifiesTheVendorSignature(t *testing.T) {
	body := []byte("a signed release")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	c := newArtifactClient(t, &artifactServer{
		body:      body,
		signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, body)),
	})
	dir := t.TempDir()

	if _, err := c.DownloadArtifact(context.Background(), "KEY", &Release{
		ArtifactSHA256:   digestOf(body),
		ArtifactFilename: "app.bin",
	}, dir, pub); err != nil {
		t.Fatalf("a correctly signed artifact was refused: %v", err)
	}
}

// The case the whole design exists for: bytes that pass the checksum but were
// not signed by the vendor.
func TestDownloadArtifactRejectsAForeignSignature(t *testing.T) {
	body := []byte("substituted release")
	_, attacker, _ := ed25519.GenerateKey(nil)
	vendorPub, _, _ := ed25519.GenerateKey(nil)

	c := newArtifactClient(t, &artifactServer{
		body:      body,
		signature: base64.StdEncoding.EncodeToString(ed25519.Sign(attacker, body)),
	})
	dir := t.TempDir()

	_, err := c.DownloadArtifact(context.Background(), "KEY", &Release{
		ArtifactSHA256:   digestOf(body),
		ArtifactFilename: "app.bin",
	}, dir, vendorPub)

	if !errors.Is(err, ErrArtifactSignature) {
		t.Fatalf("err = %v, want ErrArtifactSignature", err)
	}
	assertDirEmpty(t, dir)
}

// Asking for signature verification and getting no signature is a refusal, not
// a silent downgrade to a checksum.
func TestDownloadArtifactRejectsAnUnsignedArtifact(t *testing.T) {
	body := []byte("unsigned release")
	pub, _, _ := ed25519.GenerateKey(nil)

	c := newArtifactClient(t, &artifactServer{body: body})
	dir := t.TempDir()

	_, err := c.DownloadArtifact(context.Background(), "KEY", &Release{
		ArtifactSHA256:   digestOf(body),
		ArtifactFilename: "app.bin",
	}, dir, pub)

	if !errors.Is(err, ErrArtifactUnsigned) {
		t.Fatalf("err = %v, want ErrArtifactUnsigned", err)
	}
	assertDirEmpty(t, dir)
}

// The filename comes from the server. A path in it must not be able to place a
// file anywhere but the directory the caller asked for.
func TestDownloadArtifactCannotEscapeTheDestination(t *testing.T) {
	body := []byte("release")
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "downloads")

	for _, name := range []string{
		"../outside/escaped.bin",
		"../../escaped.bin",
		"/etc/escaped.bin",
		"",
	} {
		c := newArtifactClient(t, &artifactServer{body: body})

		path, err := c.DownloadArtifact(context.Background(), "KEY", &Release{
			ArtifactSHA256:   digestOf(body),
			ArtifactFilename: name,
		}, dest, nil)
		if err != nil {
			t.Fatalf("filename %q: %v", name, err)
		}

		resolved, err := filepath.Abs(path)
		if err != nil {
			t.Fatal(err)
		}
		wantPrefix, _ := filepath.Abs(dest)
		if !strings.HasPrefix(resolved, wantPrefix+string(filepath.Separator)) {
			t.Errorf("filename %q wrote to %q, outside %q", name, resolved, wantPrefix)
		}
	}

	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("a file was written outside the destination: %v", entries)
	}
}

func TestCheckForUpdateParsesTheOutcome(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("version"); got != "3.2.0" {
			t.Errorf("version = %q, want the current version to be sent", got)
		}
		_, _ = w.Write([]byte(`{
			"outcome": "maintenance_lapsed",
			"latest": {"version": "4.0.0", "artifact_filename": "app.bin"}
		}`))
	}))
	defer srv.Close()

	c, err := New(Config{
		ProductUUID: "p",
		PublicKeys:  map[string]ed25519.PublicKey{"k": pub},
		Cache:       &MemoryCache{},
		BaseURL:     srv.URL,
		Retries:     0,
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := c.CheckForUpdate(context.Background(), "KEY", UpdateQuery{CurrentVersion: "3.2.0"})
	if err != nil {
		t.Fatalf("CheckForUpdate: %v", err)
	}

	// A lapsed license is a renewal prompt, not a failure, and the app still
	// needs to know which version renewing would unlock.
	if res.Available() {
		t.Error("Available() true for a lapsed license")
	}
	if !res.RenewalWouldUnlock() {
		t.Error("RenewalWouldUnlock() false, so the app cannot prompt")
	}
	if res.Latest == nil || res.Latest.Version != "4.0.0" {
		t.Errorf("Latest = %+v", res.Latest)
	}
}

func assertDirEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("a refused artifact was left on disk: %v", names)
	}
}

// An artifact is an installer, often hundreds of megabytes, and
// http.Client.Timeout covers the body read. Reusing the short API timeout here
// aborted every download that took longer than ten seconds.
func TestDownloadIsNotBoundByTheAPITimeout(t *testing.T) {
	body := []byte("a release artifact that arrives slowly")
	sum := sha256.Sum256(body)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, b := range body {
			_, _ = w.Write([]byte{b})
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer srv.Close()

	pub, _, _ := ed25519.GenerateKey(nil)
	c, err := New(Config{
		ProductUUID: "p",
		PublicKeys:  map[string]ed25519.PublicKey{"k": pub},
		Cache:       &MemoryCache{},
		BaseURL:     srv.URL,
		// Shorter than the transfer takes. It must bound API calls, not this.
		Timeout: 100 * time.Millisecond,
		Retries: 0,
	})
	if err != nil {
		t.Fatal(err)
	}

	path, err := c.DownloadArtifact(context.Background(), "KEY", &Release{
		UUID:             "rel-1",
		ArtifactSHA256:   hex.EncodeToString(sum[:]),
		ArtifactFilename: "app.bin",
	}, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("a slow download was aborted by the API timeout: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(body) {
		t.Error("the artifact did not arrive intact")
	}
}
