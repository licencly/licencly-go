package main

import (
	"context"
	"fmt"

	"github.com/licencly/licencly-go"
)

var (
	publicKeys = licencly.MustParseKeys(map[string]string{
		"MCowBQYDK2VwAyEAdBuIlrXCchFV06BXkqwbWiA+xIa+rZrPslNpsCZuekw=": "dBuIlrXCchFV06BXkqwbWiA+xIa+rZrPslNpsCZuekw=",
	})
	licenseKey = "AQMZXT-YEG38H-0YS9R9-0XJS38"
)

func main() {
	client, err := licencly.New(licencly.Config{
		ProductUUID: "f8189a34-4a09-4090-ab02-7da03d0a8a4d",
		PublicKeys:  publicKeys,
		BaseURL:     "http://192.168.1.50:8080",
		Fingerprint: "foo",
	})

	if err != nil {
		panic(err)
	}

	decision, err := client.Validate(context.Background(), licenseKey)
	if err != nil && !licencly.IsNetwork(err) {
		fmt.Println("licensing:", err)
		return
	}

	if !decision.OK() {
		fmt.Println("cannot run:", decision.Outcome)
		return
	}
}
