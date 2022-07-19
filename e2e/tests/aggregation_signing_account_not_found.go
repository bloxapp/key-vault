package tests

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/bloxapp/key-vault/keymanager/models"

	"github.com/prysmaticlabs/go-bitfield"

	types "github.com/prysmaticlabs/prysm/consensus-types/primitives"

	"github.com/bloxapp/key-vault/utils/encoder/encoderv2"

	ethpb "github.com/prysmaticlabs/prysm/proto/prysm/v1alpha1"

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

	agg := &ethpb.AggregateAttestationAndProof{
		AggregatorIndex: types.ValidatorIndex(1),
		SelectionProof:  make([]byte, 96),
		Aggregate: &ethpb.Attestation{
			AggregationBits: bitfield.NewBitlist(12),
			Signature:       make([]byte, 96),
			Data: &ethpb.AttestationData{
				Slot:            types.Slot(1),
				CommitteeIndex:  types.CommitteeIndex(12),
				BeaconBlockRoot: make([]byte, 32),
				Source: &ethpb.Checkpoint{
					Epoch: types.Epoch(1),
					Root:  make([]byte, 32),
				},
				Target: &ethpb.Checkpoint{
					Epoch: types.Epoch(1),
					Root:  make([]byte, 32),
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
	require.EqualValues(t, fmt.Sprintf("1 error occurred:\n\t* failed to sign: account not found\n\n"), err.(*e2e.ServiceError).ErrorValue())
}

func (test *AggregationSigningAccountNotFound) serializedReq(pk, root, domain []byte, agg *ethpb.AggregateAttestationAndProof) (map[string]interface{}, error) {
	req := &models.SignRequest{
		PublicKey:       pk,
		SigningRoot:     root,
		SignatureDomain: domain,
		Object:          &models.SignRequestAggregateAttestationAndProof{AggregateAttestationAndProof: agg},
	}

	byts, err := encoderv2.New().Encode(req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"sign_req": hex.EncodeToString(byts),
	}, nil
}
