package tests

import (
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/utils/encoder"

	"github.com/bloxapp/key-vault/e2e"
	"github.com/bloxapp/key-vault/keymanager/models"
)

// AttestationReferenceSigning tests sign attestation endpoint.
// tested against a block and sig generated from https://github.com/prysmaticlabs/prysm/blob/master/shared/testutil/block.go#L357
type AttestationReferenceSigning struct {
}

// Name returns the name of the test.
func (test *AttestationReferenceSigning) Name() string {
	return "Test attestation reference signing"
}

// Run run the test.
func (test *AttestationReferenceSigning) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	storage := setup.UpdateStorage(t, core.PraterNetwork, true, core.NDWallet, _byteArray("2c083f2c8fc923fa2bd32a70ab72b4b46247e8c1f347adc30b2f8036a355086c"))
	// Get wallet
	wallet, err := storage.OpenWallet()
	require.NoError(t, err)
	account, err := wallet.AccountByPublicKey("a9cf360aa15fb1d1d30ee2b578dc5884823c19661886ae8b892775ccb3bd96b7d7345569a2aa0b14e4d015c54a6a0c54")
	require.NoError(t, err)
	require.NotNil(t, account)
	pubKeyBytes := account.ValidatorPublicKey()

	// Decode attestation
	attestationDataByts := _byteArray("000000000000000000000000000000003a43a4bf26fb5947e809c1f24f7dc6857c8ac007e535d48e6e4eca2122fd776b0000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000003a43a4bf26fb5947e809c1f24f7dc6857c8ac007e535d48e6e4eca2122fd776b")
	att := &phase0.AttestationData{}
	require.NoError(t, att.UnmarshalSSZ(attestationDataByts))
	domain := _byteArray32("0100000081509579e35e84020ad8751eca180b44df470332d3ad17fc6fd52459")

	// Send sign attestation request
	req, err := test.serializedReq(pubKeyBytes, nil, domain, att)
	require.NoError(t, err)
	sig, err := setup.Sign("sign", req, core.PraterNetwork)
	require.NoError(t, err)
	expectedSig := _byteArray("b4fa352d2d6dbdf884266af7ea0914451929b343527ea6c1737ac93b3dde8b7c98e6ce61d68b7a2e7b7af8f8d0fd429d0bdd5f930b83e6842bf4342d3d1d3d10fc0d15bab7649bb8aa8287ca104a1f79d396ce0217bb5cd3e6503a3bce4c9776")
	require.EqualValues(t, expectedSig, sig)
}

func (test *AttestationReferenceSigning) serializedReq(pk, root []byte, domain [32]byte, attestation *phase0.AttestationData) (map[string]interface{}, error) {
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
