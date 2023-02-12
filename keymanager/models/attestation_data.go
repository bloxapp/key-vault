package models

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// SignRequestAttestationData struct
type SignRequestAttestationData struct {
	AttestationData *phase0.AttestationData
}

// isSignRequestObject implement func
func (m *SignRequestAttestationData) isSignRequestObject() {}
