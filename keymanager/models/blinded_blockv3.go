package models

import (
	"github.com/attestantio/go-eth2-client/api"
)

// SignRequestBlindedBlock struct
type SignRequestBlindedBlock struct {
	VersionedBlindedBeaconBlock *api.VersionedBlindedBeaconBlock
}

// isSignRequestObject implement func
func (m *SignRequestBlindedBlock) isSignRequestObject() {}
