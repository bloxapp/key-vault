package models

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// SignRequestSlot struct fir sign req slot
type SignRequestSlot struct {
	Slot phase0.Slot
}

// isSignRequestObject implementation interface
func (m *SignRequestSlot) isSignRequestObject() {}
