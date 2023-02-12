package models

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// SignRequestEpoch struct
type SignRequestEpoch struct {
	Epoch phase0.Epoch
}

// isSignRequestObject implement func
func (m *SignRequestEpoch) isSignRequestObject() {}
