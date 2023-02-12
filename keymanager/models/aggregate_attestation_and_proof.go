package models

import (
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// SignRequestAggregateAttestationAndProof struct
type SignRequestAggregateAttestationAndProof struct {
	AggregateAttestationAndProof *phase0.AggregateAndProof
}

// isSignRequestObject implement func
func (m *SignRequestAggregateAttestationAndProof) isSignRequestObject() {}
