# licencly-go

Verify [Licencly](https://licencly.com) licenses and check for entitled updates,
from Go.

```
go get github.com/licencly/licencly-go
```

## The idea

The signed license file is the answer; the network is an optimisation. The
client reads its cache, refreshes when due, and keeps working through an outage
until the grace period is spent, so Licencly being unreachable never stops
software you have already sold.

## Quickstart

Copy the product UUID and public key from your Licencly dashboard and embed
them at build time. Fetching keys at runtime would defeat the whole scheme.

```go
package main

import (
	"context"
	"fmt"

	"github.com/licencly/licencly-go"
)

// From Products → your product → Signing key.
var publicKeys = licencly.MustParseKeys(map[string]string{
	"9f2c1a44-…": "MWvD7YE6HjI/DQ0kYGJFNG4kXlx4hP6ck1Vr4j77fzk=",
})

func main() {
	client, err := licencly.New(licencly.Config{
		ProductUUID: "fec65576-…",
		PublicKeys:  publicKeys,
		Fingerprint: machineID(), // yours; see below
	})
	if err != nil {
		panic(err)
	}

	decision, err := client.Validate(context.Background(), userEnteredKey)
	if err != nil && !licencly.IsNetwork(err) {
		fmt.Println("licensing error:", err)
		return
	}

	switch decision.Outcome {
	case licencly.OutcomeValid:
		// Run.
	case licencly.OutcomeNotActive:
		fmt.Println("This license has been suspended or revoked.")
	case licencly.OutcomeExpired:
		fmt.Println("This license expired. Renew to continue.")
	case licencly.OutcomeWrongMachine:
		fmt.Println("This license is in use on another machine.")
	case licencly.OutcomeStale:
		fmt.Println("Please connect to the internet to re-check your license.")
	case licencly.OutcomeInvalid:
		fmt.Println("This license file could not be verified.")
	}
}
```

`Validate` makes no network call at all while the cached file is still fresh.

## Offline

| When | Behaviour |
|---|---|
| Before `rev` | Cache only, no network |
| Between `rev` and `rev + grace` | Keeps working, refreshes in the background. `NeedsRevalidation` is true |
| After `rev + grace` | `OutcomeStale` |

A network failure inside the grace window is **not** an error your users should
see. Check `licencly.IsNetwork(err)` and stay quiet.

## Updates

```go
res, err := client.CheckForUpdate(ctx, key, licencly.UpdateQuery{
	CurrentVersion: "1.2.0",
	Platform:       runtime.GOOS,
	Arch:           runtime.GOARCH,
})

switch {
case res.Available():
	path, err := client.DownloadArtifact(ctx, key, res.Release, "/tmp/updates", artifactKey)

case res.RenewalWouldUnlock():
	// Not an error: a newer version exists and this license is not entitled
	// to it. res.Latest names what renewing would unlock.
	fmt.Printf("Version %s is available with an active maintenance plan.\n", res.Latest.Version)
}
```

Checking for updates never consumes a seat.

## Verifying downloads

`artifactKey` is **your own** Ed25519 public key, compiled into your
application, not fetched from Licencly. Licencly stores and serves the
signature but cannot produce one, so a compromise of Licencly cannot push code
to your users. `DownloadArtifact` verifies the digest and that signature before
the file is moved into place; passing `nil` reduces it to corruption detection.

Generate the keypair with the `sign` tool in the server repo, and keep the
private half off Licencly entirely.

## Machine fingerprints

The SDK does not compute one, because a good fingerprint is specific to what you
ship. It must stay stable across restarts, app updates and reboots, and survive
minor hardware change. VMs, containers and cloned disks all defeat naive
approaches. Budget more thought than it looks like it needs.

If you leave `Fingerprint` empty, machine binding is disabled and a license file
copied to another machine will still verify.

## Clock tampering

Expiry is checked against a clock the user controls; rolling it back extends an
expired license offline. This is unavoidable for anything that must work without
a network, and it is true of every offline licensing scheme.

The SDK records the furthest-forward time it has seen and rejects a jump
backwards of more than 24 hours. That is a speed bump, not a fix.

## Errors worth telling apart

| Check | Meaning |
|---|---|
| `licencly.IsNetwork(err)` | Could not reach the server. Retryable, and silent inside grace |
| `licencly.IsTampering(err)` | Signature or format failure. **Never retry** |
| `*APIError.SeatLimitReached()` | No free activations |
| `*APIError.NotFound()` | Unknown product or key |
| `*APIError.RateLimited()` | Carries `RetryAfter` |

## Conformance

`go test ./...` runs `testdata/vectors.json`, the same suite every Licencly SDK
runs. If this SDK ever disagrees with the Python, TypeScript or .NET ones, that
test fails first.
