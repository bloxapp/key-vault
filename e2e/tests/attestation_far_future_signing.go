package tests

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/utils/encoder"

	"github.com/bloxapp/key-vault/e2e"
	"github.com/bloxapp/key-vault/e2e/shared"
	"github.com/bloxapp/key-vault/keymanager/models"
)

// AttestationFarFutureSigning tests sign attestation endpoint with future signing.
type AttestationFarFutureSigning struct {
}

// Name returns the name of the test.
func (test *AttestationFarFutureSigning) Name() string {
	return "Test far future attestation (source and target) signing"
}

// Run run the test.
func (test *AttestationFarFutureSigning) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	storage := setup.UpdateStorage(t, core.PraterNetwork, true, core.HDWallet, nil)
	account := shared.RetrieveAccount(t, storage)
	require.NotNil(t, account)
	pubKeyBytes := account.ValidatorPublicKey()

	expectedSourceErr := "map[string]interface {}{\"errors\":[]interface {}{\"1 error occurred:\\n\\t* failed to sign: source epoch too far into the future\\n\\n\"}}"
	expectedTargetErr := "map[string]interface {}{\"errors\":[]interface {}{\"1 error occurred:\\n\\t* failed to sign: target epoch too far into the future\\n\\n\"}}"

	currentEpoch := core.PraterNetwork.EstimatedCurrentEpoch()
	futureEpoch := core.PraterNetwork.EstimatedCurrentEpoch() + 1000
	test.testFarFuture(t, setup, pubKeyBytes, futureEpoch, currentEpoch, expectedSourceErr) // far future source
	test.testFarFuture(t, setup, pubKeyBytes, currentEpoch, futureEpoch, expectedTargetErr) // far future target
	test.testFarFuture(t, setup, pubKeyBytes, futureEpoch, futureEpoch, expectedTargetErr)  // far future both
}

func (test *AttestationFarFutureSigning) testFarFuture(
	t *testing.T,
	setup *e2e.BaseSetup,
	pubKeyBytes []byte,
	source phase0.Epoch,
	target phase0.Epoch,
	expectedErr string,
) {
	att := &phase0.AttestationData{
		Slot:            core.PraterNetwork.EstimatedCurrentSlot() + 1000,
		Index:           phase0.CommitteeIndex(2),
		BeaconBlockRoot: _byteArray32("7b5679277ca45ea74e1deebc9d3e8c0e7d6c570b3cfaf6884be144a81dac9a0e"),
		Source: &phase0.Checkpoint{
			Epoch: source,
			Root:  _byteArray32("7402fdc1ce16d449d637c34a172b349a12b2bae8d6d77e401006594d8057c33d"),
		},
		Target: &phase0.Checkpoint{
			Epoch: target,
			Root:  _byteArray32("17959acc370274756fa5e9fdd7e7adf17204f49cc8457e49438c42c4883cbfb0"),
		},
	}
	domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")

	// Send sign attestation request
	req, err := test.serializedReq(pubKeyBytes, nil, domain, att)
	require.NoError(t, err)
	_, err = setup.Sign("sign", req, core.PraterNetwork)
	require.NotNil(t, err)
	require.EqualError(t, err, expectedErr, fmt.Sprintf("actual: %s\n", err.Error()))
}

func (test *AttestationFarFutureSigning) serializedReq(pk, root []byte, domain [32]byte, attestation *phase0.AttestationData) (map[string]interface{}, error) {
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
