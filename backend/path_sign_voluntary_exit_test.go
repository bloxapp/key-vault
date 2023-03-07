package backend

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/keymanager/models"
	"github.com/bloxapp/key-vault/utils/encoder"
)

func basicVoluntaryExitData(differentPubKey bool) map[string]interface{} {
	voluntaryExit := &phase0.VoluntaryExit{
		Epoch:          1,
		ValidatorIndex: 1,
	}

	pubKey := _byteArray("95087182937f6982ae99f9b06bd116f463f414513032e33a3d175d9662eddf162101fcf6ca2a9fedaded74b8047c5dcf")
	if differentPubKey {
		pubKey = _byteArray("95087182937f6982ae99f9b06bd116f463f414513032e33a3d175d9662eddf162101fcf6ca2a9fedaded74b8047c5dcd")
	}

	req := &models.SignRequest{
		PublicKey:       pubKey,
		SignatureDomain: _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac"),
		Object:          &models.SignRequestVoluntaryExit{VoluntaryExit: voluntaryExit},
	}

	byts, _ := encoder.New().Encode(req)
	return map[string]interface{}{
		"sign_req": hex.EncodeToString(byts),
	}
}

func TestVoluntaryExit(t *testing.T) {
	b, _ := getBackend(t)

	t.Run("Successfully sign voluntary exit", func(t *testing.T) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign-voluntary-exit")
		setupBaseStorage(t, req)

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)

		req.Data = basicVoluntaryExitData(false)
		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp.Data)
	})

	t.Run("Sign voluntary exit of unknown account", func(t *testing.T) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign-voluntary-exit")
		setupBaseStorage(t, req)

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)

		req.Data = basicVoluntaryExitData(true)
		resp, err := b.HandleRequest(context.Background(), req)
		require.NotNil(t, err)
		require.EqualError(t, err, "failed to sign: account not found")
		require.Nil(t, resp)
	})
}
