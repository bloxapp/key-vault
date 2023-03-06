package store_test

import (
	"context"
	"math/big"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/backend/store"
)

func _bigInt(input string) *big.Int {
	res, _ := new(big.Int).SetString(input, 10)
	return res
}

type mockAccount struct {
	id            uuid.UUID
	validationKey *big.Int
}

func (a *mockAccount) ID() uuid.UUID    { return a.id }
func (a *mockAccount) Name() string     { return "" }
func (a *mockAccount) BasePath() string { return "" }
func (a *mockAccount) ValidatorPublicKey() []byte {
	sk := &bls.SecretKey{}
	_ = sk.Deserialize(a.validationKey.Bytes())
	return sk.GetPublicKey().Serialize()
}
func (a *mockAccount) WithdrawalPublicKey() []byte                     { return nil }
func (a *mockAccount) ValidationKeySign(data []byte) ([]byte, error)   { return nil, nil }
func (a *mockAccount) GetDepositData() (map[string]interface{}, error) { return nil, nil }
func (a *mockAccount) SetContext(ctx *core.WalletContext)              {}

func getSlashingStorage() core.SlashingStore {
	return store.NewHashicorpVaultStore(context.Background(), &logical.InmemStorage{}, core.PraterNetwork)
}

func TestSavingProposal(t *testing.T) {
	storage := getSlashingStorage()
	tests := []struct {
		name     string
		proposal phase0.Slot
		account  core.ValidatorAccount
	}{
		{
			name:     "simple save",
			proposal: 100,
			account: &mockAccount{
				id:            uuid.New(),
				validationKey: _bigInt("5467048590701165350380985526996487573957450279098876378395441669247373404218"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// save
			err := storage.SaveHighestProposal(test.account.ValidatorPublicKey(), test.proposal)
			require.NoError(t, err)

			// fetch
			proposal, found, err := storage.RetrieveHighestProposal(test.account.ValidatorPublicKey())
			require.NoError(t, err)
			require.True(t, found)
			require.NotNil(t, proposal)

			// test equal
			require.EqualValues(t, test.proposal, proposal)
		})
	}
}

func TestSavingAttestation(t *testing.T) {
	storage := getSlashingStorage()
	tests := []struct {
		name    string
		att     *phase0.AttestationData
		account core.ValidatorAccount
	}{
		{
			name: "simple save",
			att: &phase0.AttestationData{
				Slot:            30,
				Index:           1,
				BeaconBlockRoot: [32]byte{},
				Source: &phase0.Checkpoint{
					Epoch: 1,
					Root:  [32]byte{},
				},
				Target: &phase0.Checkpoint{
					Epoch: 4,
					Root:  [32]byte{},
				},
			},
			account: &mockAccount{
				id:            uuid.New(),
				validationKey: _bigInt("5467048590701165350380985526996487573957450279098876378395441669247373404218"),
			},
		},
		{
			name: "simple save with no change to latest attestation target",
			att: &phase0.AttestationData{
				Slot:            30,
				Index:           1,
				BeaconBlockRoot: [32]byte{},
				Source: &phase0.Checkpoint{
					Epoch: 1,
					Root:  [32]byte{},
				},
				Target: &phase0.Checkpoint{
					Epoch: 3,
					Root:  [32]byte{},
				},
			},
			account: &mockAccount{
				id:            uuid.New(),
				validationKey: _bigInt("5467048590701165350380985526996487573957450279098876378395441669247373404218"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// save
			err := storage.SaveHighestAttestation(test.account.ValidatorPublicKey(), test.att)
			require.NoError(t, err)

			// fetch
			att, found, err := storage.RetrieveHighestAttestation(test.account.ValidatorPublicKey())
			require.NoError(t, err)
			require.True(t, found)
			require.NotNil(t, att)

			// test equal
			aRoot, err := att.HashTreeRoot()
			require.NoError(t, err)
			bRoot, err := test.att.HashTreeRoot()
			require.NoError(t, err)
			require.EqualValues(t, aRoot, bRoot)
		})
	}
}

func TestSavingHighestAttestation(t *testing.T) {
	storage := getSlashingStorage()
	tests := []struct {
		name    string
		att     *phase0.AttestationData
		account core.ValidatorAccount
	}{
		{
			name: "simple save",
			att: &phase0.AttestationData{
				Slot:            30,
				Index:           1,
				BeaconBlockRoot: [32]byte{},
				Source: &phase0.Checkpoint{
					Epoch: 1,
					Root:  [32]byte{},
				},
				Target: &phase0.Checkpoint{
					Epoch: 4,
					Root:  [32]byte{},
				},
			},
			account: &mockAccount{
				id:            uuid.New(),
				validationKey: _bigInt("5467048590701165350380985526996487573957450279098876378395441669247373404218"),
			},
		},
		{
			name: "simple save with no change to latest attestation target",
			att: &phase0.AttestationData{
				Slot:            30,
				Index:           1,
				BeaconBlockRoot: [32]byte{},
				Source: &phase0.Checkpoint{
					Epoch: 1,
					Root:  [32]byte{},
				},
				Target: &phase0.Checkpoint{
					Epoch: 3,
					Root:  [32]byte{},
				},
			},
			account: &mockAccount{
				id:            uuid.New(),
				validationKey: _bigInt("5467048590701165350380985526996487573957450279098876378395441669247373404218"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// save
			err := storage.SaveHighestAttestation(test.account.ValidatorPublicKey(), test.att)
			require.NoError(t, err)

			// fetch
			att, found, err := storage.RetrieveHighestAttestation(test.account.ValidatorPublicKey())
			require.NoError(t, err)
			require.True(t, found)
			require.NotNil(t, att)

			// test equal
			aRoot, err := att.HashTreeRoot()
			require.NoError(t, err)
			bRoot, err := test.att.HashTreeRoot()
			require.NoError(t, err)
			require.EqualValues(t, aRoot, bRoot)
		})
	}
}
