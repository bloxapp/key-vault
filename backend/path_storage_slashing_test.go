package backend

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/backend/store"
)

func TestSlashingStorage_Read(t *testing.T) {
	b, _ := getBackend(t)
	inMemStore, accountID, err := baseInmemStorage()
	require.NoError(t, err)

	account, err := inMemStore.OpenAccount(accountID)
	require.NoError(t, err)
	publicKey := hex.EncodeToString(account.ValidatorPublicKey())

	attestationDataSSZ := _byteArray("000000000000000000000000000000003a43a4bf26fb5947e809c1f24f7dc6857c8ac007e535d48e6e4eca2122fd776b0000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000003a43a4bf26fb5947e809c1f24f7dc6857c8ac007e535d48e6e4eca2122fd776b")
	attestation := &phase0.AttestationData{}
	require.NoError(t, attestation.UnmarshalSSZ(attestationDataSSZ))

	proposal := phase0.Slot(1)

	t.Run("successfully read slashing history", func(t *testing.T) {
		ctx := context.Background()
		req := logical.TestRequest(t, logical.ReadOperation, "storage/slashing")
		setupBaseStorage(t, req)
		newStore, err := store.FromInMemoryStore(ctx, inMemStore, req.Storage)
		require.NoError(t, err)
		err = newStore.SaveHighestAttestation(account.ValidatorPublicKey(), attestation)
		require.NoError(t, err)
		err = newStore.SaveHighestProposal(account.ValidatorPublicKey(), proposal)
		require.NoError(t, err)

		res, err := b.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.NotEmpty(t, res.Data[publicKey].(string))

		data, err := hex.DecodeString(res.Data[publicKey].(string))
		require.NoError(t, err)
		var slashingHistory SlashingHistory
		err = json.Unmarshal(data, &slashingHistory)
		require.NoError(t, err)
		decodedAttSSZ, err := slashingHistory.HighestAttestation.MarshalSSZ()
		require.NoError(t, err)
		require.EqualValues(t, attestationDataSSZ, decodedAttSSZ)

		require.EqualValues(t, proposal, slashingHistory.HighestProposal)
	})
}
