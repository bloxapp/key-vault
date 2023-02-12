package tests

import (
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/utils/encoder"

	"github.com/bloxapp/key-vault/e2e"
	"github.com/bloxapp/key-vault/e2e/shared"
	"github.com/bloxapp/key-vault/keymanager/models"
)

// AggregationConcurrentSigning tests aggregation signing method concurrently.
type AggregationConcurrentSigning struct {
}

// Name returns the name of the test.
func (test *AggregationConcurrentSigning) Name() string {
	return "Test aggregation concurrent signing"
}

// Run runs the test.
func (test *AggregationConcurrentSigning) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	store := setup.UpdateStorage(t, core.PraterNetwork, true, core.HDWallet, nil)
	account := shared.RetrieveAccount(t, store)
	pubKey := account.ValidatorPublicKey()

	// sign and save the valid aggregation
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

	// Send requests in parallel
	t.Run("concurrent signing", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 5; i++ {
			t.Run("concurrent signing "+strconv.Itoa(i), func(t *testing.T) {
				t.Parallel()

				_, err := setup.Sign("sign", req, core.PraterNetwork)
				if err == nil {
					return
				}

				require.Error(t, err)
				require.IsType(t, &e2e.ServiceError{}, err)

				errValue := err.(*e2e.ServiceError).ErrorValue()
				protected := errValue == "1 error occurred:\n\t* locked\n\n"
				require.True(t, protected, err.Error())
			})
		}
	})
}

func (test *AggregationConcurrentSigning) serializedReq(pk, root []byte, domain [32]byte, agg *phase0.AggregateAndProof) (map[string]interface{}, error) {
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
