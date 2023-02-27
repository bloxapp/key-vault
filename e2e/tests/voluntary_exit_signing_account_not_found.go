package tests

import (
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/utils/encoder"

	"github.com/bloxapp/key-vault/e2e"
	"github.com/bloxapp/key-vault/keymanager/models"
)

// VoluntaryExitSigningAccountNotFound tests sign voluntary exit when account not found
type VoluntaryExitSigningAccountNotFound struct {
}

// Name returns the name of the test
func (test *VoluntaryExitSigningAccountNotFound) Name() string {
	return "Test voluntary exit signing account not found"
}

// Run runs the test.
func (test *VoluntaryExitSigningAccountNotFound) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	setup.UpdateStorage(t, core.PraterNetwork, true, core.HDWallet, nil)

	// sign
	voluntaryExit := &phase0.VoluntaryExit{
		Epoch:          1,
		ValidatorIndex: 1,
	}
	domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")
	pubKey := _byteArray("ab321d63b7b991107a5667bf4fe853a266c2baea87d33a41c7e39a5641bfd3b5434b76f1229d452acb45ba86284e3278") // this account is not found
	req, err := test.serializedReq(pubKey, nil, domain, voluntaryExit)
	require.NoError(t, err)

	// send
	res, err := setup.Sign("sign-voluntary-exit", req, core.PraterNetwork)
	require.Error(t, err)
	require.IsType(t, &e2e.ServiceError{}, err)
	require.EqualValues(t, "1 error occurred:\n\t* failed to sign: account not found\n\n", err.(*e2e.ServiceError).ErrorValue())
	require.Nil(t, res)
}

func (test *VoluntaryExitSigningAccountNotFound) serializedReq(pk, root []byte, domain [32]byte, voluntaryExit *phase0.VoluntaryExit) (map[string]interface{}, error) {
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
