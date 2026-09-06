package licencly

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Cache stores the last good license file between runs. Without it, every
// launch needs the network and the offline guarantee is worthless.
type Cache interface {
	Load() (file string, highestSeen time.Time, err error)
	Save(file string, highestSeen time.Time) error
	Clear() error
}

// FileCache stores the file in the user's data directory.
//
// Per-user and writable without privileges on purpose: an application that
// needs admin rights to cache a license will not have them when it matters.
type FileCache struct {
	Path string
}

type cacheEnvelope struct {
	// File is stored verbatim. Re-serialising would risk changing the exact
	// bytes the signature covers.
	File string `json:"file"`
	// HighestSeen is the furthest-forward time this client has observed. A
	// large jump backwards from it is treated as clock tampering.
	HighestSeen int64 `json:"highest_seen"`
}

// DefaultCachePath returns an OS-appropriate per-user location.
func DefaultCachePath(productSlug string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "licencly", sanitize(productSlug)+".license"), nil
}

func (c *FileCache) Load() (string, time.Time, error) {
	raw, err := os.ReadFile(c.Path)
	if err != nil {
		// A missing cache is the normal first-run state, not a failure.
		return "", time.Time{}, nil
	}

	var env cacheEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		// Corrupt cache is treated as absent. Reporting it as invalid would
		// tell a user their license is broken when a disk hiccup truncated a
		// file we can simply refetch.
		return "", time.Time{}, nil
	}
	return env.File, time.Unix(env.HighestSeen, 0).UTC(), nil
}

func (c *FileCache) Save(file string, highestSeen time.Time) error {
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o700); err != nil {
		return err
	}

	raw, err := json.Marshal(cacheEnvelope{File: file, HighestSeen: highestSeen.Unix()})
	if err != nil {
		return err
	}

	// Write and rename, so an interrupted save cannot leave a half-written
	// cache that reads as corrupt on next launch.
	tmp := c.Path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.Path)
}

func (c *FileCache) Clear() error {
	if err := os.Remove(c.Path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// MemoryCache holds the file for the process lifetime only. Useful in tests and
// in short-lived jobs where writing to disk is unwelcome.
type MemoryCache struct {
	file        string
	highestSeen time.Time
}

func (c *MemoryCache) Load() (string, time.Time, error) { return c.file, c.highestSeen, nil }

func (c *MemoryCache) Save(file string, highestSeen time.Time) error {
	c.file, c.highestSeen = file, highestSeen
	return nil
}

func (c *MemoryCache) Clear() error {
	c.file, c.highestSeen = "", time.Time{}
	return nil
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "license"
	}
	return out
}
