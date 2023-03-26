package tests

import (
	"encoding/hex"
	"math/rand"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/utils/encoder"

	"github.com/bloxapp/key-vault/e2e"
	"github.com/bloxapp/key-vault/e2e/shared"
	"github.com/bloxapp/key-vault/keymanager/models"
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
	setup := e2e.Setup(t)

	// setup vault with db
	store := setup.UpdateStorage(t, core.PraterNetwork, true, core.HDWallet, nil)
	account := shared.RetrieveAccount(t, store)
	pubKey := account.ValidatorPublicKey()

	// Send requests in parallel
	wg := &sync.WaitGroup{}
	signedCnt := int64(0)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		t.Run("concurrent signing "+strconv.Itoa(i), func(t *testing.T) {
			go test.runSlashableAttestation(t, &signedCnt, wg, setup, pubKey)
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, signedCnt)
}

// will return no error if trying to sign a slashable attestation will not work
func (test *AttestationConcurrentSigning) runSlashableAttestation(t *testing.T, cnt *int64, wg *sync.WaitGroup, setup *e2e.BaseSetup, pubKey []byte) {
	defer wg.Done()

	randomCommittee := func() phase0.CommitteeIndex {
		max := 1000
		min := 2
		return phase0.CommitteeIndex(rand.Intn(max-min) + min)
	}

	att := &phase0.AttestationData{
		Slot:            phase0.Slot(284115),
		Index:           randomCommittee(),
		BeaconBlockRoot: _byteArray32("7b5679277ca45ea74e1deebc9d3e8c0e7d6c570b3cfaf6884be144a81dac9a0e"),
		Source: &phase0.Checkpoint{
			Epoch: phase0.Epoch(77),
			Root:  _byteArray32("7402fdc1ce16d449d637c34a172b349a12b2bae8d6d77e401006594d8057c33d"),
		},
		Target: &phase0.Checkpoint{
			Epoch: phase0.Epoch(78),
			Root:  _byteArray32("17959acc370274756fa5e9fdd7e7adf17204f49cc8457e49438c42c4883cbfb0"),
		},
	}
	domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")

	req, err := test.serializedReq(pubKey, nil, domain, att)
	require.NoError(t, err)

	_, err = setup.Sign("sign", req, core.PraterNetwork)
	if err == nil {
		atomic.AddInt64(cnt, 1)
	}
}

func (test *AttestationConcurrentSigning) serializedReq(pk, root []byte, domain [32]byte, attestation *phase0.AttestationData) (map[string]interface{}, error) {
	req := &models.SignRequest{
		PublicKey:       pk,
		SigningRoot:     root,
		SignatureDomain: domain,
		Object:          &models.SignRequestAttestationData{AttestationData: attestation},
	}

	byts, err := encoder.New().Encode(req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"sign_req": hex.EncodeToString(byts),
	}, nil
}
