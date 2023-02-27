package backend

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sync"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	vault "github.com/bloxapp/eth2-key-manager"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"

	"github.com/bloxapp/key-vault/backend/store"
)

// Endpoints patterns
const (
	// SlashingStoragePattern is the path pattern for slashing storage endpoint
	SlashingStoragePattern = "storage/slashing"
)

// SlashingHistory contains slashing history data.
type SlashingHistory struct {
	HighestAttestation *phase0.AttestationData
	HighestProposal    *HighestProposal
}

// HighestProposal contains highest proposal data.
type HighestProposal struct {
	Slot phase0.Slot
}

func storageSlashingDataPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern:         SlashingStoragePattern,
			HelpSynopsis:    "Manage slashing storage",
			HelpDescription: `Manage KeyVault slashing storage`,
			ExistenceCheck:  b.pathExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathMinimalSlashingStorageRead,
				},
			},
		},
	}
}

func (b *backend) pathMinimalSlashingStorageRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Load config
	config, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get config")
	}

	// bring up KeyVault and wallet
	storage := store.NewHashicorpVaultStore(ctx, req.Storage, config.Network)
	options := vault.KeyVaultOptions{}
	options.SetStorage(storage)

	// Open wallet
	kv, err := vault.OpenKeyVault(&options)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open key vault")
	}

	wallet, err := kv.Wallet()
	if err != nil {
		return nil, errors.Wrap(err, "failed to retrieve wallet")
	}

	// Load accounts slashing history
	accounts := wallet.Accounts()
	responseData := make([]map[string]interface{}, len(accounts))
	errs := make([]error, len(accounts))
	var wg sync.WaitGroup
	for i, account := range accounts {
		wg.Add(1)
		go func(i int, pubKey []byte) {
			defer wg.Done()

			// Load slashing history
			slashingHistory, err := loadAccountSlashingHistory(storage, pubKey)
			if err != nil {
				errs[i] = errors.Wrap(err, "failed to load slashing history")
				return
			}

			responseData[i] = map[string]interface{}{
				hex.EncodeToString(pubKey): slashingHistory,
			}
		}(i, account.ValidatorPublicKey())
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	historyData := make(map[string]interface{})
	for _, d := range responseData {
		for pubKey, history := range d {
			historyData[pubKey] = history
		}
	}

	return &logical.Response{
		Data: historyData,
	}, nil
}

func loadAccountSlashingHistory(storage *store.HashicorpVaultStore, pubKey []byte) (string, error) {
	errs := make([]error, 2)
	var wg sync.WaitGroup

	// Fetch attestations
	var highestAtt *phase0.AttestationData
	wg.Add(1)
	go func() {
		defer wg.Done()

		var err error
		highestAttestation, found, err := storage.RetrieveHighestAttestation(pubKey)
		if err != nil {
			errs[0] = errors.Wrap(err, "failed to retrieve highest attestation")
			return
		}
		if !found {
			errs[0] = errors.New("highest attestation not found")
			return
		}
		if highestAttestation == nil {
			errs[0] = errors.New("highest attestation is nil")
		}
		highestAtt = highestAttestation
	}()

	// Fetch proposals
	var highestProposal *HighestProposal
	wg.Add(1)
	go func() {
		defer wg.Done()

		proposal, found, err := storage.RetrieveHighestProposal(pubKey)
		if err != nil {
			errs[1] = errors.Wrap(err, "failed to retrieve highest proposal")
			return
		}
		if !found {
			errs[1] = errors.New("highest proposal not found")
			return
		}
		if proposal == 0 {
			errs[1] = errors.Wrap(err, "highest proposal is 0")
		} else {
			highestProposal = &HighestProposal{
				Slot: proposal,
			}
		}
	}()

	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return "", err
		}
	}

	slashingHistoryEncoded, err := json.Marshal(SlashingHistory{
		HighestAttestation: highestAtt,
		HighestProposal:    highestProposal,
	})
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal slashing history")
	}

	return hex.EncodeToString(slashingHistoryEncoded), nil
}
