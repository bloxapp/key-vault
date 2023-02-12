package tests

import (
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/bloxapp/key-vault/keymanager/models"

	"github.com/bloxapp/key-vault/utils/encoder"

	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/e2e"

	"github.com/bloxapp/eth2-key-manager/core"
)

// AggregationReferenceSigning tests sign aggregation endpoint.
// tested against a block and sig generated from https://github.com/prysmaticlabs/prysm/blob/develop/beacon-chain/sync/validate_aggregate_proof_test.go#L300
type AggregationReferenceSigning struct {
}

// Name returns the name of the test.
func (test *AggregationReferenceSigning) Name() string {
	return "Test aggregation reference signing"
}

// Run run the test.
func (test *AggregationReferenceSigning) Run(t *testing.T) {
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

	// decode object
	agg := &phase0.AggregateAndProof{}
	aggAttByts := _byteArray("01000000000000006c000000b4fa352d2d6dbdf884266af7ea0914451929b343527ea6c1737ac93b3dde8b7c98e6ce61d68b7a2e7b7af8f8d0fd429d0bdd5f930b83e6842bf4342d3d1d3d10fc0d15bab7649bb8aa8287ca104a1f79d396ce0217bb5cd3e6503a3bce4c9776e4000000000000000000000000000000000000003a43a4bf26fb5947e809c1f24f7dc6857c8ac007e535d48e6e4eca2122fd776b0000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000003a43a4bf26fb5947e809c1f24f7dc6857c8ac007e535d48e6e4eca2122fd776bb4fa352d2d6dbdf884266af7ea0914451929b343527ea6c1737ac93b3dde8b7c98e6ce61d68b7a2e7b7af8f8d0fd429d0bdd5f930b83e6842bf4342d3d1d3d10fc0d15bab7649bb8aa8287ca104a1f79d396ce0217bb5cd3e6503a3bce4c97760010")
	require.NoError(t, agg.UnmarshalSSZ(aggAttByts))
	domain := _byteArray32("0100000081509579e35e84020ad8751eca180b44df470332d3ad17fc6fd52459")
	req, err := test.serializedReq(pubKeyBytes, nil, domain, agg)
	require.NoError(t, err)

	// Send sign attestation request
	sig, err := setup.Sign("sign", req, core.PraterNetwork)
	require.NoError(t, err)
	expectedSig := _byteArray("a8333dee0d7a20d99d13f870c3b77e413b7755c1640985fc70bc58f6004b50f43ef301147208c9c5393258d7e9b2208316c48d540879e2818352b346d8ce6d91ce8c1942758ab5425a0448959ea46609397c0dc9c05708f243389af694fda91c")
	require.EqualValues(t, expectedSig, sig)
}

func (test *AggregationReferenceSigning) serializedReq(pk, root []byte, domain [32]byte, agg *phase0.AggregateAndProof) (map[string]interface{}, error) {
	req := &models.SignRequest{
		PublicKey:       pk,
		SigningRoot:     root,
		SignatureDomain: domain,
		Object:          &models.SignRequestAggregateAttestationAndProof{AggregateAttestationAndProof: agg},
	}

	byts, err := encoder.New().Encode(req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"sign_req": hex.EncodeToString(byts),
	}, nil
}
