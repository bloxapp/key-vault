package tests

import (
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/bloxapp/key-vault/keymanager/models"

	"github.com/bloxapp/key-vault/utils/encoder"

	"github.com/stretchr/testify/require"

	"github.com/bloxapp/eth2-key-manager/core"

	"github.com/bloxapp/key-vault/e2e"
)

// AggregationProofReferenceSigning tests sign aggregation endpoint.
// tested against a block and sig generated from https://github.com/prysmaticlabs/prysm/blob/develop/beacon-chain/sync/validate_aggregate_proof_test.go#L300
type AggregationProofReferenceSigning struct {
}

// Name returns the name of the test.
func (test *AggregationProofReferenceSigning) Name() string {
	return "Test aggregation proof reference signing"
}

// Run run the test.
func (test *AggregationProofReferenceSigning) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	storage := setup.UpdateStorage(t, core.PraterNetwork, true, core.NDWallet, _byteArray("6327b1e58c41d60dd7c3c8b9634204255707c2d12e2513c345001d8926745eea"))
	// Get wallet
	wallet, err := storage.OpenWallet()
	require.NoError(t, err)
	account, err := wallet.AccountByPublicKey("954eb88ed1207f891dc3c28fa6cfdf8f53bf0ed3d838f3476c0900a61314d22d4f0a300da3cd010444dd5183e35a593c")
	require.NoError(t, err)
	require.NotNil(t, account)
	pubKeyBytes := account.ValidatorPublicKey()

	// decode object
	slot := uint64(0)
	domain := _byteArray32("050000008c84cda94176cc2b1268357c57c3160131874a4408e155b0db826d11")
	req, err := test.serializedReq(pubKeyBytes, nil, domain, slot)
	require.NoError(t, err)

	// Send sign attestation request
	sig, err := setup.Sign("sign", req, core.PraterNetwork)
	require.NoError(t, err)
	expectedSig := _byteArray("a1167cdbebeae876b3fa82d4f4c35fc3dc4706c7ae20cee359919fdbc93a2588c3f7a15c80d12a20c78ac6381a9fe35d06f6b8ae7e95fb87fa2195511bd53ce6f385aa71dda52b38771f954348a57acad9dde225da614c50c02173314417b096")
	require.EqualValues(t, expectedSig, sig)
}

func (test *AggregationProofReferenceSigning) serializedReq(pk, root []byte, domain [32]byte, slot uint64) (map[string]interface{}, error) {
	req := &models.SignRequest{
		PublicKey:       pk,
		SigningRoot:     root,
		SignatureDomain: domain,
		Object:          &models.SignRequestSlot{Slot: phase0.Slot(slot)},
	}

	byts, err := encoder.New().Encode(req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"sign_req": hex.EncodeToString(byts),
	}, nil
}
