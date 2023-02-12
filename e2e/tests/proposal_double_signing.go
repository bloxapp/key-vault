package tests

import (
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/utils/encoder"

	"github.com/bloxapp/key-vault/e2e"
	"github.com/bloxapp/key-vault/e2e/shared"
	"github.com/bloxapp/key-vault/keymanager/models"
)

// ProposalDoubleSigning tests signing method concurrently.
type ProposalDoubleSigning struct {
}

// Name returns the name of the test.
func (test *ProposalDoubleSigning) Name() string {
	return "Test proposal double signing"
}

// Run runs the test.
func (test *ProposalDoubleSigning) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	store := setup.UpdateStorage(t, core.PraterNetwork, true, core.HDWallet, nil)
	account := shared.RetrieveAccount(t, store)
	pubKey := account.ValidatorPublicKey()

	// Sign and save the valid proposal
	blk := referenceBlock(t)
	domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")
	req, err := test.serializedReq(pubKey, nil, domain, blk)
	require.NoError(t, err)
	_, err = setup.Sign("sign", req, core.PraterNetwork)
	require.NoError(t, err)

	// Sign and save the slashable proposa
	blk.Phase0.ParentRoot = _byteArray32("7b5679277ca45ea74e1deebc9d3e8c0e7d6c570b3cfaf6884be144a81dac9a0d")
	req, err = test.serializedReq(pubKey, nil, domain, blk)
	require.NoError(t, err)
	_, err = setup.Sign("sign", req, core.PraterNetwork)
	require.Error(t, err, "did not slash")
	require.IsType(t, &e2e.ServiceError{}, err)

	errValue := err.(*e2e.ServiceError).ErrorValue()
	protected := errValue == "1 error occurred:\n\t* failed to sign: slashable proposal (HighestProposalVote), not signing\n\n"
	require.True(t, protected, err.Error())
}

func (test *ProposalDoubleSigning) serializedReq(pk, root []byte, domain [32]byte, blk *spec.VersionedBeaconBlock) (map[string]interface{}, error) {
	req := &models.SignRequest{
		PublicKey:       pk,
		SigningRoot:     root,
		SignatureDomain: domain,
		Object:          &models.SignRequestBlock{VersionedBeaconBlock: blk},
	}

	byts, err := encoder.New().Encode(req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"sign_req": hex.EncodeToString(byts),
	}, nil
}
