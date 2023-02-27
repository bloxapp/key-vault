package models

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// SignRequestVoluntaryExit struct
type SignRequestVoluntaryExit struct {
	VoluntaryExit *phase0.VoluntaryExit
}

// isSignRequestObject implement func
func (m *SignRequestVoluntaryExit) isSignRequestObject() {}
