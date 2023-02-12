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

// RandaoReferenceSigning tests sign proposal endpoint.
type RandaoReferenceSigning struct {
}

// Name returns the name of the test.
// tested against a block and sig generated from https://github.com/prysmaticlabs/prysm/blob/master/shared/testutil/block.go#L86
func (test *RandaoReferenceSigning) Name() string {
	return "Test randao reference signing"
}

// Run run the test.
func (test *RandaoReferenceSigning) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	storage := setup.UpdateStorage(t, core.PraterNetwork, true, core.NDWallet, _byteArray("5470813f7deef638dc531188ca89e36976d536f680e89849cd9077fd096e20bc"))
	// Get wallet
	wallet, err := storage.OpenWallet()
	require.NoError(t, err)
	account, err := wallet.AccountByPublicKey("a3862121db5914d7272b0b705e6e3c5336b79e316735661873566245207329c30f9a33d4fb5f5857fc6fd0a368186972")
	require.NoError(t, err)
	require.NotNil(t, account)
	pubKeyBytes := account.ValidatorPublicKey()

	// Send sign attestation request
	domain := _byteArray32("0200000081509579e35e84020ad8751eca180b44df470332d3ad17fc6fd52459")
	req, err := test.serializedReq(pubKeyBytes, nil, domain, 0)
	require.NoError(t, err)
	sig, err := setup.Sign("sign", req, core.PraterNetwork)
	require.NoError(t, err)

	expectedSig := _byteArray("a2c156a4bc9439f1d85f922f2abaa96e830f1c526101211bdb7d16f4ad9490a0302fc5adb089c05b5f16fd465962f47c04fc2b81a94d135a07c1613db61511c17284b51fafab984e56d3411e16e45f5068f146d9412f91d31ab0f237eac3d745")
	require.Equal(t, expectedSig, sig)
}

func (test *RandaoReferenceSigning) serializedReq(pk, root []byte, domain [32]byte, epoch uint64) (map[string]interface{}, error) {
	req := &models.SignRequest{
		PublicKey:       pk,
		SigningRoot:     root,
		SignatureDomain: domain,
		Object:          &models.SignRequestEpoch{Epoch: phase0.Epoch(epoch)},
	}

	byts, err := encoder.New().Encode(req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"sign_req": hex.EncodeToString(byts),
	}, nil
}
