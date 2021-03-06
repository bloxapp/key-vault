package tests

import (
	"encoding/hex"
	"testing"

	eth "github.com/prysmaticlabs/ethereumapis/eth/v1alpha1"
	validatorpb "github.com/prysmaticlabs/prysm/proto/validator/accounts/v2"

	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/e2e"
)

// ProposalSigningAccountNotFound tests sign attestation when account not found
type ProposalSigningAccountNotFound struct {
}

// Name returns the name of the test
func (test *ProposalSigningAccountNotFound) Name() string {
	return "Test proposal signing account not found"
}

// Run runs the test.
func (test *ProposalSigningAccountNotFound) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	setup.UpdateStorage(t, core.PyrmontNetwork, true, core.HDWallet, nil)

	// sign
	blk := referenceBlock(t)
	domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")
	req, err := test.serializedReq(make([]byte, 48), nil, domain, blk)
	require.NoError(t, err)

	_, err = setup.Sign("sign", req, core.PyrmontNetwork)
	require.Error(t, err)
	require.IsType(t, &e2e.ServiceError{}, err)
	require.EqualValues(t, "1 error occurred:\n\t* failed to sign: account not found\n\n", err.(*e2e.ServiceError).ErrorValue())
}

func (test *ProposalSigningAccountNotFound) serializedReq(pk, root, domain []byte, blk *eth.BeaconBlock) (map[string]interface{}, error) {
	req := &validatorpb.SignRequest{
		PublicKey:       pk,
		SigningRoot:     root,
		SignatureDomain: domain,
		Object:          &validatorpb.SignRequest_Block{Block: blk},
	}

	byts, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"sign_req": hex.EncodeToString(byts),
	}, nil
}
