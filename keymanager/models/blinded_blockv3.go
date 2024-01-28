package models

import (
	"github.com/attestantio/go-eth2-client/api"
)

// SignRequestBlindedBlock struct
type SignRequestBlindedBlock struct {
	VersionedBlindedBeaconBlock *api.VersionedBlindedProposal
}

// isSignRequestObject implement func
func (m *SignRequestBlindedBlock) isSignRequestObject() {}
