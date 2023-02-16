package store_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	eth2keymanager "github.com/bloxapp/eth2-key-manager"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/bloxapp/eth2-key-manager/encryptor"
	"github.com/bloxapp/eth2-key-manager/encryptor/keystorev4"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/backend/store"
)

func getStorage() logical.Storage {
	return &logical.InmemStorage{}
}

func keyVault(storage core.Storage) (*eth2keymanager.KeyVault, error) {
	if err := core.InitBLS(); err != nil {
		os.Exit(1)
	}

	options := &eth2keymanager.KeyVaultOptions{}
	options.SetStorage(storage)
	return eth2keymanager.NewKeyVault(options)
}

func getWalletStorage() core.Storage {
	return store.NewHashicorpVaultStore(context.Background(), getStorage(), core.PraterNetwork)
}

func TestOpeningAccounts(t *testing.T) {
	storage := getWalletStorage()
	kv, err := keyVault(storage)
	require.NoError(t, err)

	wallet, err := kv.Wallet()
	require.NoError(t, err)

	seed := _byteArray("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fff")

	for i := 0; i < 10; i++ {
		testName := fmt.Sprintf("adding and fetching account: %d", i)
		t.Run(testName, func(t *testing.T) {
			// create
			a, err := wallet.CreateValidatorAccount(seed, nil)
			require.NoError(t, err)

			// open
			a1, err := wallet.AccountByPublicKey(hex.EncodeToString(a.ValidatorPublicKey()))
			require.NoError(t, err)

			a2, err := wallet.AccountByID(a.ID())
			require.NoError(t, err)

			// verify
			for _, fetchedAccount := range []core.ValidatorAccount{a1, a2} {
				require.Equal(t, a.ID().String(), fetchedAccount.ID().String())
				require.Equal(t, a.Name(), fetchedAccount.Name())
				require.Equal(t, a.ValidatorPublicKey(), fetchedAccount.ValidatorPublicKey())
				require.Equal(t, a.WithdrawalPublicKey(), fetchedAccount.WithdrawalPublicKey())
			}
		})
	}
}

func TestNonExistingWallet(t *testing.T) {
	storage := getWalletStorage()
	w, err := storage.OpenWallet()
	require.NotNil(t, err)
	require.EqualError(t, err, "wallet not found")
	require.Nil(t, w)
}

func TestWalletStorage(t *testing.T) {
	storage := getWalletStorage()
	tests := []struct {
		name       string
		walletName string
		encryptor  encryptor.Encryptor
		password   []byte
		error
	}{
		{
			name:       "serialization and fetching",
			walletName: "test1",
		},
		{
			name:       "serialization and fetching with encryptor",
			walletName: "test2",
			encryptor:  keystorev4.New(),
			password:   []byte("password"),
		},
	}

	kv, err := keyVault(storage)
	require.NoError(t, err)

	wallet, err := kv.Wallet()
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// set encryptor
			if test.encryptor != nil {
				storage.SetEncryptor(test.encryptor, test.password)
			} else {
				storage.SetEncryptor(nil, nil)
			}

			err = storage.SaveWallet(wallet)
			if err != nil {
				if test.error != nil {
					require.Equal(t, test.error.Error(), err.Error())
				} else {
					t.Error(err)
				}
				return
			}

			// fetch wallet by id
			fetched, err := storage.OpenWallet()
			if err != nil {
				if test.error != nil {
					require.Equal(t, test.error.Error(), err.Error())
				} else {
					t.Error(err)
				}
				return
			}

			require.NotNil(t, fetched)
			require.NoError(t, test.error)

			// assert
			require.Equal(t, wallet.ID(), fetched.ID())
			require.Equal(t, wallet.Type(), fetched.Type())
		})
	}

	// reset
	storage.SetEncryptor(nil, nil)
}
