package tests

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/e2e"
	"github.com/bloxapp/key-vault/keymanager/models"
	"github.com/bloxapp/key-vault/utils/encoder"
)

// ProposalSigningAccountNotFound tests sign attestation when account not found
type ProposalSigningAccountNotFound struct {
	BlockVersion spec.DataVersion
}

// Name returns the name of the test
func (test *ProposalSigningAccountNotFound) Name() string {
	return fmt.Sprintf("Test proposal signing account not found: %s", test.BlockVersion.String())
}

// Run runs the test.
func (test *ProposalSigningAccountNotFound) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	setup.UpdateStorage(t, core.PraterNetwork, true, core.HDWallet, nil)

	// sign
	blk := referenceBlockByVersion(t, test.BlockVersion)
	domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")
	req, err := test.serializedReq(make([]byte, 48), nil, domain, blk)
	require.NoError(t, err)

	_, err = setup.Sign("sign", req, core.PraterNetwork)
	require.Error(t, err)
	require.IsType(t, &e2e.ServiceError{}, err)
	require.EqualValues(t, "1 error occurred:\n\t* failed to sign: account not found\n\n", err.(*e2e.ServiceError).ErrorValue())
}

func (test *ProposalSigningAccountNotFound) serializedReq(pk, root []byte, domain [32]byte, blk *spec.VersionedBeaconBlock) (map[string]interface{}, error) {
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
