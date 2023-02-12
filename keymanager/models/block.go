package models

import (
	"github.com/attestantio/go-eth2-client/spec"
)

// SignRequestBlock struct
type SignRequestBlock struct {
	VersionedBeaconBlock *spec.VersionedBeaconBlock
}

// isSignRequestObject implement func
func (m *SignRequestBlock) isSignRequestObject() {}
