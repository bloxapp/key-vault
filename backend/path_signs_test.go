package backend

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	eth2apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/keymanager/models"
	"github.com/bloxapp/key-vault/utils/encoder"
)

func setupStorageWithWalletAndAccounts(storage logical.Storage) error {
	_, err := baseHashicorpStorage(context.Background(), storage)
	return err
}

func basicAggregationAndProofData() map[string]interface{} {
	return basicAggregationAndProofDataWithOps(false)
}

func basicAggregationAndProofDataWithOps(undefinedPubKey bool) map[string]interface{} {
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

	req := &models.SignRequest{
		PublicKey:       _byteArray("95087182937f6982ae99f9b06bd116f463f414513032e33a3d175d9662eddf162101fcf6ca2a9fedaded74b8047c5dcf"),
		SigningRoot:     nil,
		SignatureDomain: _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac"),
		Object:          &models.SignRequestAggregateAttestationAndProof{AggregateAttestationAndProof: agg},
	}

	if undefinedPubKey {
		req.PublicKey = _byteArray("95087182937f6982ae99f9b06bd116f463f414513032e33a3d175d9662eddf162101fcf6ca2a9fedaded74b8047c5dcd")
	}

	byts, _ := encoder.New().Encode(req)
	return map[string]interface{}{
		"sign_req": hex.EncodeToString(byts),
	}
}

func TestSignAttestation(t *testing.T) {
	b, _ := getBackend(t)

	// t.Run("Sign Attestation in non existing key vault", func(t *testing.T) {
	//	req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
	//	setupBaseStorage(t, req)
	//	_, err := b.HandleRequest(context.Background(), req)
	//	require.EqualError(t, err, "failed to sign: failed to open key vault: wallet not found")
	// })

	t.Run("Sign Attestation of unknown account", func(t *testing.T) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
		setupBaseStorage(t, req)

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)

		req.Data = basicAttestationDataWithOps(true, false, false, false, false)
		resp, err := b.HandleRequest(context.Background(), req)
		require.NotNil(t, err)
		require.EqualError(t, err, "failed to sign: account not found")
		require.Nil(t, resp)
	})
}

func TestSignProposal(t *testing.T) {
	b, _ := getBackend(t)

	withEachBlockVersion(t, "Successfully Sign Proposal", func(t *testing.T, blockVersion spec.DataVersion, isBlinded bool) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
		setupBaseStorage(t, req)

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)

		data := basicProposalData(blockVersion, isBlinded)
		req.Data = data
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, res.Data)
	})

	// t.Run("Sign Proposal in non existing key vault", func(t *testing.T) {
	//	req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
	//	setupBaseStorage(t, req)
	//	_, err := b.HandleRequest(context.Background(), req)
	//	require.EqualError(t, err, "failed to sign: failed to open key vault: wallet not found")
	// })

	withEachBlockVersion(t, "Sign Proposal of unknown account", func(t *testing.T, blockVersion spec.DataVersion, isBlinded bool) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
		setupBaseStorage(t, req, func(c *Config) {
			c.FeeRecipients["0x95087182937f6982ae99f9b06bd116f463f414513032e33a3d175d9662eddf162101fcf6ca2a9fedaded74b8047c5dcd"] = "0x6a3f3ee924a940ce0d795c5a41a817607e520520"
		})

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)

		req.Data = basicProposalDataWithOps(blockVersion, false, true, false, false, false)
		resp, err := b.HandleRequest(context.Background(), req)
		require.NotNil(t, err)
		require.EqualError(t, err, "failed to sign: account not found")
		require.Nil(t, resp)
	})
}

func TestSignAggregation(t *testing.T) {
	b, _ := getBackend(t)

	t.Run("Successfully Sign Aggregation", func(t *testing.T) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
		setupBaseStorage(t, req)

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)

		req.Data = basicAggregationAndProofData()
		_, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
	})

	// t.Run("Sign Aggregation in non existing key vault", func(t *testing.T) {
	//	req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
	//	setupBaseStorage(t, req)
	//	_, err := b.HandleRequest(context.Background(), req)
	//	require.EqualError(t, err, "failed to sign: failed to open key vault: wallet not found")
	// })

	t.Run("Sign Aggregation of unknown account", func(t *testing.T) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
		setupBaseStorage(t, req)

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)

		req.Data = basicAggregationAndProofDataWithOps(true)
		resp, err := b.HandleRequest(context.Background(), req)
		require.NotNil(t, err)
		require.EqualError(t, err, "failed to sign: account not found")
		require.Nil(t, resp)
	})
}

func TestSignRegistration(t *testing.T) {
	b, _ := getBackend(t)

	t.Run("Sign validator registration", func(t *testing.T) {
		validatorRegistration := &eth2apiv1.ValidatorRegistration{}
		jsonData := []byte(`{"fee_recipient":"0x9831eef7a86c19e32becdad091c1dbc974cf452a","gas_limit":"123456","timestamp":"1658313712","pubkey":"0x95087182937f6982ae99f9b06bd116f463f414513032e33a3d175d9662eddf162101fcf6ca2a9fedaded74b8047c5dcf"}`)
		err := json.Unmarshal(jsonData, validatorRegistration)
		require.NoError(t, err)

		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
		setupBaseStorage(t, req, func(c *Config) {
			c.FeeRecipients = FeeRecipients{hexutil.Encode(validatorRegistration.Pubkey[:]): hexutil.Encode(validatorRegistration.FeeRecipient[:])}
		})

		// setup storage
		err = setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)

		byts, err := encoder.New().Encode(&models.SignRequest{
			PublicKey:       validatorRegistration.Pubkey[:],
			SigningRoot:     nil,
			SignatureDomain: _byteArray32("00000001f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9"),
			// Object :
			Object: &models.SignRequestRegistration{
				VersionedValidatorRegistration: &api.VersionedValidatorRegistration{
					V1: validatorRegistration,
				},
			},
		})
		require.NoError(t, err)
		req.Data = map[string]interface{}{
			"sign_req": hex.EncodeToString(byts),
		}
		resp, err := b.HandleRequest(context.Background(), req)
		require.Nil(t, err)
		require.Equal(t, "ac1694a323372f7e40e5366d5ceb5167f23557c6415bdbab6e26f62f10de42b7e979238c6c00124846af6fd3d804961e084ba1ccd5280521fb75d81baf9ccac2450df00c7c749b711cdeb0dd5b9ffa0d7738369d25196ea839557377f3a7b356", resp.Data["signature"])
	})
}

func TestValidateRequestedFeeRecipient(t *testing.T) {
	recipient := func(lastByte byte) string { return hexutil.Encode(append(bytes.Repeat([]byte{0}, 19), lastByte)) }
	pubKey := func(lastByte byte) string { return hexutil.Encode(append(bytes.Repeat([]byte{0}, 95), lastByte)) }

	tests := []struct {
		name               string
		configured         FeeRecipients
		requestedValidator string
		requestedRecipient string
		expectedErr        error
	}{
		{
			name: "Good",
			configured: FeeRecipients{
				pubKey(1): recipient(1),
				pubKey(2): recipient(2),
				"default": recipient(3),
			},
			requestedValidator: pubKey(1),
			requestedRecipient: recipient(1),
			expectedErr:        nil,
		},
		{
			name: "Default",
			configured: FeeRecipients{
				pubKey(1): recipient(1),
				pubKey(2): recipient(2),
				"default": recipient(3),
			},
			requestedValidator: pubKey(3),
			requestedRecipient: recipient(3),
			expectedErr:        nil,
		},
		{
			name: "Wrong default",
			configured: FeeRecipients{
				pubKey(1): recipient(1),
				pubKey(2): recipient(2),
				"default": recipient(3),
			},
			requestedValidator: pubKey(3),
			requestedRecipient: recipient(4),
			expectedErr:        ErrFeeRecipientDiffers,
		},
		{
			name: "Differs from configuration",
			configured: FeeRecipients{
				pubKey(1): recipient(1),
				pubKey(2): recipient(2),
				"default": recipient(3),
			},
			requestedValidator: pubKey(1),
			requestedRecipient: recipient(2),
			expectedErr:        ErrFeeRecipientDiffers,
		},
		{
			name: "No such validator",
			configured: FeeRecipients{
				pubKey(1): recipient(1),
				pubKey(2): recipient(2),
			},
			requestedValidator: pubKey(3),
			requestedRecipient: recipient(2),
			expectedErr:        ErrFeeRecipientNotSet,
		},
		{
			name: "No such recipient",
			configured: FeeRecipients{
				pubKey(1): recipient(1),
				pubKey(2): recipient(2),
				"default": recipient(3),
			},
			requestedValidator: pubKey(1),
			requestedRecipient: recipient(4),
			expectedErr:        ErrFeeRecipientDiffers,
		},
		{
			name: "Other validator's recipient",
			configured: FeeRecipients{
				pubKey(1): recipient(1),
				pubKey(2): recipient(2),
				"default": recipient(3),
			},
			requestedValidator: pubKey(1),
			requestedRecipient: recipient(2),
			expectedErr:        ErrFeeRecipientDiffers,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var feeRecipient bellatrix.ExecutionAddress
			recipientBytes := hexutil.MustDecode(test.requestedRecipient)
			copy(feeRecipient[:], recipientBytes)
			err := validateRequestedFeeRecipient(hexutil.MustDecode(test.requestedValidator), test.configured, feeRecipient)
			require.Equal(t, test.expectedErr, err)
		})
	}
}
