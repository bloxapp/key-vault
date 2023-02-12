package tests

import (
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/e2e"
	"github.com/bloxapp/key-vault/e2e/shared"
	"github.com/bloxapp/key-vault/keymanager/models"
	"github.com/bloxapp/key-vault/utils/encoder"
)

// AggregationDoubleSigning tests aggregation signing method concurrently.
type AggregationDoubleSigning struct {
}

// Name returns the name of the test.
func (test *AggregationDoubleSigning) Name() string {
	return "Test aggregation double signing"
}

// Run runs the test.
func (test *AggregationDoubleSigning) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	store := setup.UpdateStorage(t, core.PraterNetwork, true, core.HDWallet, nil)
	account := shared.RetrieveAccount(t, store)
	pubKey := account.ValidatorPublicKey()

	agg := &phase0.AggregateAndProof{
		AggregatorIndex: phase0.ValidatorIndex(1),
		SelectionProof:  [96]byte{},
		Aggregate: &phase0.Attestation{
			AggregationBits: bitfield.NewBitlist(12),
			Signature:       [96]byte{},
			Data: &phase0.AttestationData{
				Slot:            phase0.Slot(1),
				Index:           phase0.CommitteeIndex(12),
				BeaconBlockRoot: [32]byte{},
				Source: &phase0.Checkpoint{
					Epoch: phase0.Epoch(1),
					Root:  [32]byte{},
				},
				Target: &phase0.Checkpoint{
					Epoch: phase0.Epoch(1),
					Root:  [32]byte{},
				},
			},
		},
	}
	domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")
	req, err := test.serializedReq(pubKey, nil, domain, agg)
	require.NoError(t, err)
	_, err = setup.Sign("sign", req, core.PraterNetwork)
	require.NoError(t, err)

	_, err = setup.Sign("sign", req, core.PraterNetwork)
	require.NoError(t, err)
}

func (test *AggregationDoubleSigning) serializedReq(pk, root []byte, domain [32]byte, agg *phase0.AggregateAndProof) (map[string]interface{}, error) {
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
