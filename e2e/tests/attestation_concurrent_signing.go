package tests

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bloxapp/vault-plugin-secrets-eth2.0/e2e"
)

// AttestationConcurrentSigning tests signing method concurrently.
type AttestationConcurrentSigning struct {
}

// Name returns the name of the test.
func (test *AttestationConcurrentSigning) Name() string {
	return "Test attestation concurrent signing"
}

// Run runs the test.
func (test *AttestationConcurrentSigning) Run(t *testing.T) {
	setup := e2e.SetupE2EEnv(t)

	// setup vault with db
	err := setup.UpdateStorage()
	require.NoError(t, err)

	// sign and save the valid attestation
	_, err = setup.SignAttestation(
		map[string]interface{}{
			"public_key":      "ab321d63b7b991107a5667bf4fe853a266c2baea87d33a41c7e39a5641bfd3b5434b76f1229d452acb45ba86284e3279",
			"domain":          "01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac",
			"slot":            284115,
			"committeeIndex":  1,
			"beaconBlockRoot": "7b5679277ca45ea74e1deebc9d3e8c0e7d6c570b3cfaf6884be144a81dac9a0e",
			"sourceEpoch":     8877,
			"sourceRoot":      "7402fdc1ce16d449d637c34a172b349a12b2bae8d6d77e401006594d8057c33d",
			"targetEpoch":     8878,
			"targetRoot":      "17959acc370274756fa5e9fdd7e7adf17204f49cc8457e49438c42c4883cbfb0",
		},
	)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		go func() {
			wg.Add(1)
			require.NoError(t, test.runSlashableAttestation(setup))
			wg.Done()
		}()
	}
	wg.Wait()

	// cleanup
	setup.Cleanup(t)
}

// will return no error if trying to sign a slashable attestation will not work
func (test *AttestationConcurrentSigning) runSlashableAttestation(setup *e2e.BaseSetup) error {
	randomCommittee := func() int {
		max := 1000
		min := 2
		return rand.Intn(max-min) + min
	}

	_, err := setup.SignAttestation(
		map[string]interface{}{
			"public_key":      "ab321d63b7b991107a5667bf4fe853a266c2baea87d33a41c7e39a5641bfd3b5434b76f1229d452acb45ba86284e3279",
			"domain":          "01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac",
			"slot":            284115,
			"committeeIndex":  randomCommittee(),
			"beaconBlockRoot": "7b5679277ca45ea74e1deebc9d3e8c0e7d6c570b3cfaf6884be144a81dac9a0e",
			"sourceEpoch":     8877,
			"sourceRoot":      "7402fdc1ce16d449d637c34a172b349a12b2bae8d6d77e401006594d8057c33d",
			"targetEpoch":     8878,
			"targetRoot":      "17959acc370274756fa5e9fdd7e7adf17204f49cc8457e49438c42c4883cbfb0",
		},
	)
	if err == nil {
		return fmt.Errorf("did not slash")
	} else if err.Error() == fmt.Sprintf("1 error occurred:\n\t* failed to sign attestation: slashable attestation (DoubleVote), not signing\n\n") {
		return nil
	} else if err.Error() == fmt.Sprintf("1 error occurred:\n\t* locked\n\n") {
		return nil
	}
	return err
}
