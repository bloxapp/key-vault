package backend

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/bloxapp/eth2-key-manager/stores/inmemory"
	"github.com/bloxapp/eth2-key-manager/wallets/hd"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/backend/store"
)

func _byteArray(input string) []byte {
	res, _ := hex.DecodeString(input)
	return res
}

func _byteArray32(input string) [32]byte {
	res, _ := hex.DecodeString(input)
	var res32 [32]byte
	copy(res32[:], res)
	return res32
}

func baseInmemStorage() (*inmemory.InMemStore, uuid.UUID, error) {
	inMemStore := inmemory.NewInMemStore(core.PraterNetwork)

	// wallet
	wallet := hd.NewWallet(&core.WalletContext{Storage: inMemStore})
	err := inMemStore.SaveWallet(wallet)
	if err != nil {
		return nil, uuid.UUID{}, err
	}

	// account
	acc, err := wallet.CreateValidatorAccount(
		_byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fff"),
		nil,
	)
	if err != nil {
		return nil, uuid.UUID{}, err
	}
	acc.ID()

	if err := inMemStore.SaveAccount(acc); err != nil {
		return nil, uuid.UUID{}, err
	}

	err = inMemStore.SaveHighestAttestation(acc.ValidatorPublicKey(), &phase0.AttestationData{
		Source: &phase0.Checkpoint{
			Epoch: 0,
			Root:  phase0.Root{},
		},
		Target: &phase0.Checkpoint{
			Epoch: 0,
			Root:  phase0.Root{},
		},
	})
	if err != nil {
		return nil, uuid.UUID{}, err
	}

	err = inMemStore.SaveHighestProposal(acc.ValidatorPublicKey(), phase0.Slot(1))
	if err != nil {
		return nil, uuid.UUID{}, err
	}

	return inMemStore, acc.ID(), nil
}

func baseHashicorpStorage(ctx context.Context, logicalStorage logical.Storage) (*store.HashicorpVaultStore, error) {
	inMem, _, err := baseInmemStorage()
	if err != nil {
		return nil, err
	}
	return store.FromInMemoryStore(ctx, inMem, logicalStorage)
}

func TestStorage(t *testing.T) {
	b, _ := getBackend(t)
	inMemStore, _, err := baseInmemStorage()
	require.NoError(t, err)

	// marshal and to string
	byts, err := json.Marshal(inMemStore)
	require.NoError(t, err)
	data := hex.EncodeToString(byts)

	getVault := func(tt *testing.T) *store.HashicorpVaultStore {
		req := logical.TestRequest(tt, logical.CreateOperation, "storage")
		req.Data = map[string]interface{}{
			"data": data,
		}
		setupBaseStorage(t, req)

		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(tt, err)
		require.True(tt, res.Data["status"].(bool))
		return store.NewHashicorpVaultStore(context.Background(), req.Storage, core.PraterNetwork)
	}

	t.Run("verify wallet and account", func(t *testing.T) {
		vault := getVault(t)
		wallet, err := vault.OpenWallet()
		require.NoError(t, err)
		require.Equal(t, wallet.ID().String(), wallet.ID().String())

		_, err = wallet.AccountByPublicKey("95087182937f6982ae99f9b06bd116f463f414513032e33a3d175d9662eddf162101fcf6ca2a9fedaded74b8047c5dcf")
		require.NoError(t, err)
	})

	t.Run("verify highest att.", func(t *testing.T) {
		vault := getVault(t)
		wallet, err := vault.OpenWallet()
		require.NoError(t, err)
		acc, err := wallet.AccountByPublicKey("95087182937f6982ae99f9b06bd116f463f414513032e33a3d175d9662eddf162101fcf6ca2a9fedaded74b8047c5dcf")
		require.NoError(t, err)

		att, err := vault.RetrieveHighestAttestation(acc.ValidatorPublicKey())
		require.NoError(t, err)
		require.NotNil(t, att)
		require.EqualValues(t, att.Source.Epoch, 0)
		require.EqualValues(t, att.Target.Epoch, 0)
	})
}
