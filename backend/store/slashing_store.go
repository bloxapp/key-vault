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
	if attestation == nil || pubKey == nil {
		return errors.Errorf("pubKey and attestation must not be nil")
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
func (store *HashicorpVaultStore) RetrieveHighestAttestation(pubKey []byte) (*phase0.AttestationData, error) {
	if pubKey == nil {
		return nil, nil
	}

	path := fmt.Sprintf(WalletHighestAttestationPath+"%s", store.identifierFromKey(pubKey))
	entry, err := store.storage.Get(store.ctx, path)
	if err != nil {
		return nil, err
	}

	// Return nothing if there is no record
	if entry == nil {
		return nil, nil
	}

	ret := &phase0.AttestationData{}
	if err := store.encoder.Decode(entry.Value, ret); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal attestation (size %d) - (hex: %s)", len(entry.Value), hex.EncodeToString(entry.Value))
	}

	return ret, nil
}

// SaveHighestProposal implements Storage interface.
func (store *HashicorpVaultStore) SaveHighestProposal(pubKey []byte, slot phase0.Slot) error {
	if slot == 0 || pubKey == nil {
		return errors.Errorf("pubKey and block must not be nil")
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
func (store *HashicorpVaultStore) RetrieveHighestProposal(pubKey []byte) (phase0.Slot, error) {
	if pubKey == nil {
		return 0, nil
	}

	path := fmt.Sprintf(WalletHighestProposalsBase, store.identifierFromKey(pubKey))
	entry, err := store.storage.Get(store.ctx, path)
	if err != nil {
		return 0, err
	}

	// Return nothing if there is no record
	if entry == nil {
		return 0, nil
	}

	ret := ssz.UnmarshallUint64(entry.Value)
	return phase0.Slot(ret), nil
}

func (store *HashicorpVaultStore) identifierFromKey(key []byte) string {
	return hex.EncodeToString(key)
}
