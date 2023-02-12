package models

import (
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// ISignObject interface
type ISignObject interface {
	isSignRequestObject()
}

// SSZBytes --
type SSZBytes []byte

// SignRequest implementing ISignObject
type SignRequest struct {
	PublicKey       []byte      `json:"public_key,omitempty"`
	SigningRoot     []byte      `json:"signing_root,omitempty"`
	SignatureDomain [32]byte    `json:"signature_domain,omitempty"`
	Object          ISignObject `json:"object,omitempty"`
}

// GetPublicKey return publicKey
func (x *SignRequest) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

// GetSigningRoot return root bytes
func (x *SignRequest) GetSigningRoot() []byte {
	if x != nil {
		return x.SigningRoot
	}
	return nil
}

// GetSignatureDomain return domain bytes
func (x *SignRequest) GetSignatureDomain() phase0.Domain {
	if x != nil {
		return x.SignatureDomain
	}
	return phase0.Domain{}
}

// GetObject return ISignObject interface
func (x *SignRequest) GetObject() ISignObject {
	if x != nil {
		return x.Object
	}
	return nil
}

// GetBlock return versioned block
func (x *SignRequest) GetBlock() *spec.VersionedBeaconBlock {
	if x, ok := x.GetObject().(*SignRequestBlock); ok {
		return x.VersionedBeaconBlock
	}
	return nil
}

// GetAttestationData return AttestationData
func (x *SignRequest) GetAttestationData() *phase0.AttestationData {
	if x, ok := x.GetObject().(*SignRequestAttestationData); ok {
		return x.AttestationData
	}
	return nil
}

// GetAggregateAttestationAndProof return AggregateAttestationAndProof
func (x *SignRequest) GetAggregateAttestationAndProof() *phase0.AggregateAndProof {
	if x, ok := x.GetObject().(*SignRequestAggregateAttestationAndProof); ok {
		return x.AggregateAttestationAndProof
	}
	return nil
}

// GetExit return VoluntaryExit
func (x *SignRequest) GetExit() *phase0.VoluntaryExit {
	if x, ok := x.GetObject().(*SignRequestExit); ok {
		return x.Exit
	}
	return nil
}

// GetSlot return types slot
func (x *SignRequest) GetSlot() phase0.Slot {
	if x, ok := x.GetObject().(*SignRequestSlot); ok {
		return x.Slot
	}
	return phase0.Slot(0)
}

// GetEpoch return types epoch
func (x *SignRequest) GetEpoch() phase0.Epoch {
	if x, ok := x.GetObject().(*SignRequestEpoch); ok {
		return x.Epoch
	}
	return phase0.Epoch(0)
}

// GetBlindedBlock return a versioned blinded block block.
func (x *SignRequest) GetBlindedBlock() *api.VersionedBlindedBeaconBlock {
	if x, ok := x.GetObject().(*SignRequestBlindedBlock); ok {
		return x.VersionedBlindedBeaconBlock
	}
	return nil
}

// GetSyncAggregatorSelectionData return SyncAggregatorSelectionData
func (x *SignRequest) GetSyncAggregatorSelectionData() *altair.SyncAggregatorSelectionData {
	if x, ok := x.GetObject().(*SignRequestSyncAggregatorSelectionData); ok {
		return x.SyncAggregatorSelectionData
	}
	return nil
}

// GetContributionAndProof return ContributionAndProof
func (x *SignRequest) GetContributionAndProof() *altair.ContributionAndProof {
	if x, ok := x.GetObject().(*SignRequestContributionAndProof); ok {
		return x.ContributionAndProof
	}
	return nil
}

// GetSyncCommitteeMessage return types SSZBytes
func (x *SignRequest) GetSyncCommitteeMessage() SSZBytes {
	if x, ok := x.GetObject().(*SignRequestSyncCommitteeMessage); ok {
		return x.Root
	}
	return nil
}

// GetRegistration return a versioned validator registration.
func (x *SignRequest) GetRegistration() *api.VersionedValidatorRegistration {
	if x, ok := x.GetObject().(*SignRequestRegistration); ok {
		return x.VersionedValidatorRegistration
	}
	return nil
}
