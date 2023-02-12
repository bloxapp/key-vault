package tests

import (
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/bloxapp/key-vault/keymanager/models"

	"github.com/prysmaticlabs/go-bitfield"

	"github.com/bloxapp/key-vault/utils/encoder"

	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/e2e"
)

// AggregationSigningAccountNotFound tests sign aggregation when account not found
type AggregationSigningAccountNotFound struct {
}

// Name returns the name of the test
func (test *AggregationSigningAccountNotFound) Name() string {
	return "Test aggregation signing account not found"
}

// Run runs the test.
func (test *AggregationSigningAccountNotFound) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	setup.UpdateStorage(t, core.PraterNetwork, true, core.HDWallet, nil)

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
	req, err := test.serializedReq(make([]byte, 48), nil, domain, agg)
	require.NoError(t, err)
	_, err = setup.Sign("sign", req, core.PraterNetwork)
	require.Error(t, err)
	require.IsType(t, &e2e.ServiceError{}, err)
	require.EqualValues(t, "1 error occurred:\n\t* failed to sign: account not found\n\n", err.(*e2e.ServiceError).ErrorValue())
}

func (test *AggregationSigningAccountNotFound) serializedReq(pk, root []byte, domain [32]byte, agg *phase0.AggregateAndProof) (map[string]interface{}, error) {
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
