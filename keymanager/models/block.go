package models

import (
	"github.com/attestantio/go-eth2-client/api"
)

// SignRequestBlock struct
type SignRequestBlock struct {
	VersionedBeaconBlock *api.VersionedProposal
}

// isSignRequestObject implement func
func (m *SignRequestBlock) isSignRequestObject() {}
