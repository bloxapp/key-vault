package shared

import (
	"fmt"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/bloxapp/eth2-key-manager/stores/inmemory"
	"github.com/bloxapp/eth2-key-manager/wallets"
	"github.com/bloxapp/eth2-key-manager/wallets/hd"
	"github.com/bloxapp/eth2-key-manager/wallets/nd"
)

// AccountIndex is the test account index.
const AccountIndex = 0

// BaseInmemStorage creates the in-memory storage and creates the base account.
func BaseInmemStorage(t *testing.T, minimalSlashingData bool, walletType core.WalletType, privKey []byte) (*inmemory.InMemStore, error) {
	err := core.InitBLS()
	require.NoError(t, err)

	store := inmemory.NewInMemStore(core.PraterNetwork)

	// wallet
	walletCtx := &core.WalletContext{Storage: store}

	// account
	var acc core.ValidatorAccount
	if walletType == core.NDWallet {
		wallet := nd.NewWallet(walletCtx)
		if err := store.SaveWallet(wallet); err != nil {
			return nil, err
		}
		k, err := core.NewHDKeyFromPrivateKey(privKey, "")
		require.NoError(t, err)
		acc = wallets.NewValidatorAccount("", k, k.PublicKey().Serialize(), "", walletCtx)
		require.NoError(t, wallet.AddValidatorAccount(acc))
	} else {
		wallet := hd.NewWallet(walletCtx)
		if err := store.SaveWallet(wallet); err != nil {
			return nil, err
		}
		acc, err = wallet.CreateValidatorAccount(newSeed(t), nil)
		if err != nil {
			return nil, err
		}
		err = store.SaveAccount(acc)
		if err != nil {
			return nil, err
		}
	}

	// base highest att.
	if minimalSlashingData {
		err = store.SaveHighestAttestation(acc.ValidatorPublicKey(), &phase0.AttestationData{
			Source: &phase0.Checkpoint{
				Epoch: 0,
				Root:  [32]byte{},
			},
			Target: &phase0.Checkpoint{
				Epoch: 0,
				Root:  [32]byte{},
			},
		})
		if err != nil {
			return nil, err
		}

		highestProposal := phase0.Slot(1)
		err = store.SaveHighestProposal(acc.ValidatorPublicKey(), highestProposal)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}

// RetrieveAccount retrieves test account fro the storage.
func RetrieveAccount(t *testing.T, store core.Storage) core.ValidatorAccount {
	accounts, err := store.ListAccounts()
	require.NoError(t, err)

	for _, acc := range accounts {
		if acc.BasePath() == fmt.Sprintf("/%d", AccountIndex) {
			return acc
		}
	}
	return nil
}

func newSeed(t *testing.T) []byte {
	entropy, err := core.GenerateNewEntropy()
	require.NoError(t, err)

	seed, err := core.SeedFromEntropy(entropy, "")
	require.NoError(t, err)
	return seed
}
