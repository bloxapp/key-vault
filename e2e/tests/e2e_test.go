package tests

import (
	"testing"

	"github.com/attestantio/go-eth2-client/spec"
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
	&RandaoReferenceSigning{},

	// Accounts tests
	&AccountsList{},

	// Config tests
	&ConfigRead{},
	&ConfigUpdate{},

	// Voluntary Exit tests
	&VoluntaryExitSigning{},
	&VoluntaryExitSigningAccountNotFound{},
}

func versionedTests(version spec.DataVersion) []E2E {
	return []E2E{
		// Proposal signing
		&ProposalSigning{BlockVersion: version},
		&ProposalDoubleSigning{BlockVersion: version},
		&ProposalConcurrentSigning{BlockVersion: version},
		&ProposalSigningAccountNotFound{BlockVersion: version},
		&ProposalFarFutureSigning{BlockVersion: version},
		&ProposalReferenceSigning{BlockVersion: version},

		// Storage tests
		&SlashingStorageRead{BlockVersion: version},
	}
}

func TestE2E(t *testing.T) {
	for _, version := range []spec.DataVersion{spec.DataVersionPhase0, spec.DataVersionDeneb} {
		tests = append(tests, versionedTests(version)...)
	}
	for _, tst := range tests {
		t.Run(tst.Name(), func(t *testing.T) {
			tst.Run(t)
		})
	}
}
