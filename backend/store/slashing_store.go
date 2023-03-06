package store

import (
	"encoding/hex"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

// Paths
const (
	WalletHighestAttestationPath = "highestAttestations/"
	WalletHighestProposalsBase   = "proposals/%s" // account/proposal
)

// SaveHighestAttestation saves highest attestation
func (store *HashicorpVaultStore) SaveHighestAttestation(pubKey []byte, attestation *phase0.AttestationData) error {
	if pubKey == nil {
		return errors.New("pubKey must not be nil")
	}

	if attestation == nil {
		return errors.New("attestation data could not be nil")
	}

	path := fmt.Sprintf(WalletHighestAttestationPath+"%s", store.identifierFromKey(pubKey))
	data, err := store.encoder.Encode(attestation)
	if err != nil {
		return errors.Wrap(err, "failed to marshal attestation request")
	}

	return store.storage.Put(store.ctx, &logical.StorageEntry{
		Key:      path,
		Value:    data,
		SealWrap: false,
	})
}

// RetrieveHighestAttestation retrieves highest attestation
func (store *HashicorpVaultStore) RetrieveHighestAttestation(pubKey []byte) (*phase0.AttestationData, bool, error) {
	if pubKey == nil {
		return nil, false, errors.New("public key could not be nil")
	}

	path := fmt.Sprintf(WalletHighestAttestationPath+"%s", store.identifierFromKey(pubKey))
	entry, err := store.storage.Get(store.ctx, path)
	if err != nil {
		return nil, false, err
	}

	// Return nothing if there is no record
	if entry == nil {
		return nil, false, nil
	}

	ret := &phase0.AttestationData{}
	if err := store.encoder.Decode(entry.Value, ret); err != nil {
		return nil, false, errors.Wrapf(err, "failed to unmarshal attestation (size %d) - (hex: %s)", len(entry.Value), hex.EncodeToString(entry.Value))
	}

	return ret, true, nil
}

// SaveHighestProposal implements Storage interface.
func (store *HashicorpVaultStore) SaveHighestProposal(pubKey []byte, slot phase0.Slot) error {
	if pubKey == nil {
		return errors.New("pubKey must not be nil")
	}

	if slot == 0 {
		return errors.New("invalid proposal slot, slot could not be 0")
	}

	path := fmt.Sprintf(WalletHighestProposalsBase, store.identifierFromKey(pubKey))
	data, err := store.encoder.Encode(slot)
	if err != nil {
		return errors.Wrap(err, "failed to marshal proposal request")
	}

	return store.storage.Put(store.ctx, &logical.StorageEntry{
		Key:      path,
		Value:    data,
		SealWrap: false,
	})
}

// RetrieveHighestProposal implements Storage interface.
func (store *HashicorpVaultStore) RetrieveHighestProposal(pubKey []byte) (phase0.Slot, bool, error) {
	if pubKey == nil {
		return 0, false, errors.New("public key could not be nil")
	}

	path := fmt.Sprintf(WalletHighestProposalsBase, store.identifierFromKey(pubKey))
	entry, err := store.storage.Get(store.ctx, path)
	if err != nil {
		return 0, false, err
	}

	// Return nothing if there is no record
	if entry == nil {
		return 0, false, nil
	}

	return phase0.Slot(ssz.UnmarshallUint64(entry.Value)), true, nil
}

func (store *HashicorpVaultStore) identifierFromKey(key []byte) string {
	return hex.EncodeToString(key)
}
