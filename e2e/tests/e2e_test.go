package tests

import (
	"testing"
)

type E2E interface {
	Name() string
	Run(t *testing.T)
}

var tests = []E2E{
	// Attestation signing
	&AttestationSigning{},
	&AttestationSigningAccountNotFound{},
	&AttestationDoubleSigning{},
	&AttestationConcurrentSigning{},
	&AttestationFarFutureSigning{},
	&AttestationNoSlashingDataSigning{},
	&AttestationReferenceSigning{},

	//Aggregation signing
	&AggregationSigning{},
	&AggregationDoubleSigning{},
	&AggregationConcurrentSigning{},
	&AggregationSigningAccountNotFound{},
	&AggregationReferenceSigning{},
	&AggregationProofReferenceSigning{},

	// Proposal signing
	&ProposalSigning{},
	&ProposalDoubleSigning{},
	&ProposalConcurrentSigning{},
	&ProposalSigningAccountNotFound{},
	&ProposalFarFutureSigning{},
	&ProposalReferenceSigning{},
	&RandaoReferenceSigning{},

	// Accounts tests
	&AccountsList{},

	// Config tests
	&ConfigRead{},
	&ConfigUpdate{},

	// Storage tests
	&SlashingStorageRead{},

	// Voluntary Exit tests
	&VoluntaryExitSigning{},
	&VoluntaryExitSigningAccountNotFound{},
}

func TestE2E(t *testing.T) {
	for _, tst := range tests {
		t.Run(tst.Name(), func(t *testing.T) {
			tst.Run(t)
		})
	}
}
