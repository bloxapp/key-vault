package tests

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/e2e"
	"github.com/bloxapp/key-vault/e2e/shared"
	"github.com/bloxapp/key-vault/keymanager/models"
	"github.com/bloxapp/key-vault/utils/encoder"
)

// ProposalFarFutureSigning tests sign proposal endpoint with future signing.
type ProposalFarFutureSigning struct {
	BlockVersion spec.DataVersion
}

// Name returns the name of the test.
func (test *ProposalFarFutureSigning) Name() string {
	return fmt.Sprintf("Test proposal far future signing: %s", test.BlockVersion.String())
}

// Run run the test.
func (test *ProposalFarFutureSigning) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	storage := setup.UpdateStorage(t, core.PraterNetwork, true, core.HDWallet, nil)
	account := shared.RetrieveAccount(t, storage)
	require.NotNil(t, account)
	pubKeyBytes := account.ValidatorPublicKey()

	blk := referenceBlockByVersion(t, test.BlockVersion)
	changeBlkSlot(t, blk, core.PraterNetwork.EstimatedCurrentSlot()+200)
	domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")
	req, err := test.serializedReq(pubKeyBytes, nil, domain, blk)
	require.NoError(t, err)
	_, err = setup.Sign("sign", req, core.PraterNetwork)
	require.NotNil(t, err)
	expectedErr := "map[string]interface {}{\"errors\":[]interface {}{\"1 error occurred:\\n\\t* failed to sign: proposed block slot too far into the future\\n\\n\"}}"
	require.EqualError(t, err, expectedErr, fmt.Sprintf("actual: %s\n", err.Error()))
}

func (test *ProposalFarFutureSigning) serializedReq(pk, root []byte, domain [32]byte, blk *spec.VersionedBeaconBlock) (map[string]interface{}, error) {
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
