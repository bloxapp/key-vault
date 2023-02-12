package models

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// SignRequestExit struct
type SignRequestExit struct {
	Exit *phase0.VoluntaryExit
}

// isSignRequestObject implement func
func (m *SignRequestExit) isSignRequestObject() {}
