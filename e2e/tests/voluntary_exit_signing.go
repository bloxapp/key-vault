package tests

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/bloxapp/eth2-key-manager/signer"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/utils/encoder"

	"github.com/bloxapp/key-vault/e2e"
	"github.com/bloxapp/key-vault/e2e/shared"
	"github.com/bloxapp/key-vault/keymanager/models"
)

// VoluntaryExitSigning tests sign voluntary exit endpoint.
type VoluntaryExitSigning struct {
}

// Name returns the name of the test.
func (test *VoluntaryExitSigning) Name() string {
	return "Test voluntary exit signing"
}

// Run run the test.
func (test *VoluntaryExitSigning) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	storage := setup.UpdateStorage(t, core.PraterNetwork, true, core.HDWallet, nil)
	account := shared.RetrieveAccount(t, storage)
	require.NotNil(t, account)
	pubKeyBytes := account.ValidatorPublicKey()

	// Get wallet
	wallet, err := storage.OpenWallet()
	require.NoError(t, err)

	voluntaryExit := &phase0.VoluntaryExit{
		Epoch:          1,
		ValidatorIndex: 1,
	}
	domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")

	// Sign data
	var signer signer.ValidatorSigner = signer.NewSimpleSigner(wallet, nil, storage.Network())

	res, _, err := signer.SignVoluntaryExit(voluntaryExit, domain, pubKeyBytes)
	require.NoError(t, err)

	// Send sign voluntary exit request
	req, err := test.serializedReq(pubKeyBytes, nil, domain, voluntaryExit)
	require.NoError(t, err)
	signedVoluntaryExitByts, err := setup.Sign("sign-voluntary-exit", req, core.PraterNetwork)
	require.NoError(t, err)
	var signedVoluntaryExit *phase0.SignedVoluntaryExit
	require.NoError(t, json.Unmarshal(signedVoluntaryExitByts, &signedVoluntaryExit))
	require.EqualValues(t, res, signedVoluntaryExit.Signature[:])
}

func (test *VoluntaryExitSigning) serializedReq(pk, root []byte, domain [32]byte, voluntaryExit *phase0.VoluntaryExit) (map[string]interface{}, error) {
	req := &models.SignRequest{
		PublicKey:       pk,
		SigningRoot:     root,
		SignatureDomain: domain,
		Object:          &models.SignRequestVoluntaryExit{VoluntaryExit: voluntaryExit},
	}

	byts, err := encoder.New().Encode(req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"sign_req": hex.EncodeToString(byts),
	}, nil
}
