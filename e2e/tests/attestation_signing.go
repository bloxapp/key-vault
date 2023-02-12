package tests

import (
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/bloxapp/eth2-key-manager/signer"
	slashingprotection "github.com/bloxapp/eth2-key-manager/slashing_protection"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/utils/encoder"

	"github.com/bloxapp/key-vault/e2e"
	"github.com/bloxapp/key-vault/e2e/shared"
	"github.com/bloxapp/key-vault/keymanager/models"
)

func _byteArray(input string) []byte {
	res, _ := hex.DecodeString(input)
	return res
}

func _byteArray32(input string) [32]byte {
	res, _ := hex.DecodeString(input)
	var res32 [32]byte
	copy(res32[:], res)
	return res32
}

// AttestationSigning tests sign attestation endpoint.
type AttestationSigning struct {
}

// Name returns the name of the test.
func (test *AttestationSigning) Name() string {
	return "Test attestation signing"
}

// Run run the test.
func (test *AttestationSigning) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	storage := setup.UpdateStorage(t, core.PraterNetwork, true, core.HDWallet, nil)
	account := shared.RetrieveAccount(t, storage)
	require.NotNil(t, account)
	pubKeyBytes := account.ValidatorPublicKey()

	// Get wallet
	wallet, err := storage.OpenWallet()
	require.NoError(t, err)

	att := &phase0.AttestationData{
		Slot:            phase0.Slot(284115),
		Index:           phase0.CommitteeIndex(2),
		BeaconBlockRoot: _byteArray32("7b5679277ca45ea74e1deebc9d3e8c0e7d6c570b3cfaf6884be144a81dac9a0e"),
		Source: &phase0.Checkpoint{
			Epoch: phase0.Epoch(5),
			Root:  _byteArray32("7402fdc1ce16d449d637c34a172b349a12b2bae8d6d77e401006594d8057c33d"),
		},
		Target: &phase0.Checkpoint{
			Epoch: phase0.Epoch(6),
			Root:  _byteArray32("17959acc370274756fa5e9fdd7e7adf17204f49cc8457e49438c42c4883cbfb0"),
		},
	}
	domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")

	// Sign data
	protector := slashingprotection.NewNormalProtection(storage)
	var signer signer.ValidatorSigner = signer.NewSimpleSigner(wallet, protector, storage.Network())

	res, _, err := signer.SignBeaconAttestation(att, domain, pubKeyBytes)
	require.NoError(t, err)

	// Send sign attestation request
	req, err := test.serializedReq(pubKeyBytes, nil, domain, att)
	require.NoError(t, err)
	sig, err := setup.Sign("sign", req, core.PraterNetwork)
	require.NoError(t, err)
	require.EqualValues(t, res, sig)
}

func (test *AttestationSigning) serializedReq(pk, root []byte, domain [32]byte, attestation *phase0.AttestationData) (map[string]interface{}, error) {
	req := &models.SignRequest{
		PublicKey:       pk,
		SigningRoot:     root,
		SignatureDomain: domain,
		Object:          &models.SignRequestAttestationData{AttestationData: attestation},
	}

	byts, err := encoder.New().Encode(req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"sign_req": hex.EncodeToString(byts),
	}, nil
}
