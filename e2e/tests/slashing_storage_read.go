package tests

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/utils/encoder"

	"github.com/bloxapp/key-vault/e2e"
	"github.com/bloxapp/key-vault/e2e/shared"
	"github.com/bloxapp/key-vault/keymanager/models"
)

type slashingHistoryModel struct {
	Data map[string]string `json:"data"`
}

// SlashingStorageRead tests slashing storage reading endpoint.
type SlashingStorageRead struct {
}

// Name returns the name of the test.
func (test *SlashingStorageRead) Name() string {
	return "Test slashing storage read"
}

// Run run the test.
func (test *SlashingStorageRead) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	storage := setup.UpdateStorage(t, core.PraterNetwork, true, core.HDWallet, nil)
	account := shared.RetrieveAccount(t, storage)
	require.NotNil(t, account)
	pubKey := account.ValidatorPublicKey()

	blk := referenceBlock(t)
	domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")
	req, err := test.serializedReq(pubKey, nil, domain, blk)
	require.NoError(t, err)

	_, err = setup.Sign("sign", req, core.PraterNetwork)
	require.NoError(t, err)

	// Read slashing storage
	storageBytes, statusCode := setup.ReadSlashingStorage(t, core.PraterNetwork)
	require.Equal(t, http.StatusOK, statusCode, string(storageBytes))

	var slashingHistory slashingHistoryModel
	err = json.Unmarshal(storageBytes, &slashingHistory)
	require.NoError(t, err)

	pubKeyHistory, ok := slashingHistory.Data[hex.EncodeToString(pubKey)]
	require.True(t, ok)
	require.NotEmpty(t, pubKeyHistory)
}

func (test *SlashingStorageRead) serializedReq(pk, root []byte, domain [32]byte, blk *api.VersionedProposal) (map[string]interface{}, error) {
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
