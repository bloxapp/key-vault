package models

import (
	"github.com/attestantio/go-eth2-client/spec/altair"
)

// SignRequestContributionAndProof struct
type SignRequestContributionAndProof struct {
	ContributionAndProof *altair.ContributionAndProof
}

// isSignRequestObject implement func
func (m *SignRequestContributionAndProof) isSignRequestObject() {}
