package backend

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/utils/encoder"

	"github.com/bloxapp/key-vault/backend/store"
	"github.com/bloxapp/key-vault/keymanager/models"
)

func basicAttestationData() map[string]interface{} {
	return basicAttestationDataWithOps(false, false, false, false, false)
}

func basicAttestationDataWithOps(differentPubKey, differentBlockRoot, differentSourceRoot, differentTargetRoot, differentDomain bool) map[string]interface{} {
	att := &phase0.AttestationData{
		Slot:            284115,
		Index:           2,
		BeaconBlockRoot: _byteArray32("7b5679277ca45ea74e1deebc9d3e8c0e7d6c570b3cfaf6884be144a81dac9a0e"),
		Source: &phase0.Checkpoint{
			Epoch: 77,
			Root:  _byteArray32("7402fdc1ce16d449d637c34a172b349a12b2bae8d6d77e401006594d8057c33d"),
		},
		Target: &phase0.Checkpoint{
			Epoch: 78,
			Root:  _byteArray32("17959acc370274756fa5e9fdd7e7adf17204f49cc8457e49438c42c4883cbfb0"),
		},
	}

	if differentBlockRoot {
		att.BeaconBlockRoot = _byteArray32("7b5679277ca45ea74e1deebc9d3e8c0e7d6c570b3cfaf6884be144a81dac9a0d")
	}
	if differentSourceRoot {
		att.Source.Root = _byteArray32("7402fdc1ce16d449d637c34a172b349a12b2bae8d6d77e401006594d8057c333")
	}
	if differentTargetRoot {
		att.Target.Root = _byteArray32("17959acc370274756fa5e9fdd7e7adf17204f49cc8457e49438c42c4883cbfb1")
	}

	domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")
	if differentDomain {
		domain = _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dad")
	}
	pubKey := _byteArray("95087182937f6982ae99f9b06bd116f463f414513032e33a3d175d9662eddf162101fcf6ca2a9fedaded74b8047c5dcf")
	if differentPubKey {
		pubKey = _byteArray("95087182937f6982ae99f9b06bd116f463f414513032e33a3d175d9662eddf162101fcf6ca2a9fedaded74b8047c5dcd")
	}

	return reqObject(
		att,
		domain,
		pubKey,
	)
}

func reqObject(att *phase0.AttestationData, domain phase0.Domain, pubKey []byte) map[string]interface{} {
	req := &models.SignRequest{
		PublicKey:       pubKey,
		SigningRoot:     nil,
		SignatureDomain: domain,
		Object:          &models.SignRequestAttestationData{AttestationData: att},
	}

	byts, _ := encoder.New().Encode(req)
	return map[string]interface{}{
		"sign_req": hex.EncodeToString(byts),
	}
}

func updateWithBasicHighestAtt(storage logical.Storage) error {
	s := store.NewHashicorpVaultStore(context.Background(), storage, core.PraterNetwork)
	pubKey, _ := hex.DecodeString("95087182937f6982ae99f9b06bd116f463f414513032e33a3d175d9662eddf162101fcf6ca2a9fedaded74b8047c5dcf")
	return s.SaveHighestAttestation(pubKey, &phase0.AttestationData{
		Source: &phase0.Checkpoint{
			Epoch: 0,
			Root:  phase0.Root{},
		},
		Target: &phase0.Checkpoint{
			Epoch: 0,
			Root:  phase0.Root{},
		},
	})
}

func TestAttestationSlashing(t *testing.T) {
	b, _ := getBackend(t)

	t.Run("Successfully Sign Attestation", func(t *testing.T) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
		setupBaseStorage(t, req)

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)
		require.NoError(t, updateWithBasicHighestAtt(req.Storage))

		req.Data = basicAttestationData()
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, res.Data)
		require.Equal(t,
			"866c25f50559c26d70a2918b29f1a1eb4e36a5cc4834ac114cec2e4ab59e8a69a23444a3a904512744caf0bfa34bd0510e436d4e1c9d66f17ed6f03a03a44baf18f8b164c69006b5538e0f4de904e66d470e5c73f0863aee220033f5f13ec050",
			res.Data["signature"],
		)
	})

	t.Run("Sign duplicated Attestation (exactly same), should NOT sign", func(t *testing.T) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
		setupBaseStorage(t, req)

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)
		require.NoError(t, updateWithBasicHighestAtt(req.Storage))

		// first attestation
		req.Data = basicAttestationData()
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, res.Data)

		// duplicated attestation
		req.Data = basicAttestationData()
		res, err = b.HandleRequest(context.Background(), req)
		require.EqualError(t, err, "failed to sign: slashable attestation (HighestAttestationVote), not signing")
		require.Nil(t, res)
	})

	t.Run("Sign double Attestation (different block root), should return error", func(t *testing.T) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
		setupBaseStorage(t, req)

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)
		require.NoError(t, updateWithBasicHighestAtt(req.Storage))

		// first attestation
		req.Data = basicAttestationData()
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, res.Data)

		// slashable attestation
		data := basicAttestationDataWithOps(false, true, false, false, false)
		req.Data = data
		res, err = b.HandleRequest(context.Background(), req)
		require.Error(t, err)
		require.EqualError(t, err, "failed to sign: slashable attestation (HighestAttestationVote), not signing")
		require.Nil(t, res)
	})

	t.Run("Sign double Attestation (different source root), should return error", func(t *testing.T) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
		setupBaseStorage(t, req)

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)
		require.NoError(t, updateWithBasicHighestAtt(req.Storage))

		// first attestation
		req.Data = basicAttestationData()
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, res.Data)

		// slashable attestation
		req.Data = basicAttestationDataWithOps(false, false, true, false, false)
		res, err = b.HandleRequest(context.Background(), req)
		require.Error(t, err)
		require.EqualError(t, err, "failed to sign: slashable attestation (HighestAttestationVote), not signing")
		require.Nil(t, res)
	})

	t.Run("Sign double Attestation (different target root), should return error", func(t *testing.T) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
		setupBaseStorage(t, req)

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)
		require.NoError(t, updateWithBasicHighestAtt(req.Storage))

		// first attestation
		req.Data = basicAttestationData()
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, res.Data)

		// slashable attestation
		req.Data = basicAttestationDataWithOps(false, false, false, true, false)
		res, err = b.HandleRequest(context.Background(), req)
		require.Error(t, err)
		require.EqualError(t, err, "failed to sign: slashable attestation (HighestAttestationVote), not signing")
		require.Nil(t, res)
	})

	t.Run("Sign Attestation (different domain), should sign", func(t *testing.T) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
		setupBaseStorage(t, req)

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)
		require.NoError(t, updateWithBasicHighestAtt(req.Storage))

		// first attestation
		req.Data = basicAttestationData()
		res, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, res.Data)

		// slashable attestation
		req.Data = basicAttestationDataWithOps(false, false, false, false, true)
		res, err = b.HandleRequest(context.Background(), req)
		require.EqualError(t, err, "failed to sign: slashable attestation (HighestAttestationVote), not signing")
		require.Nil(t, res)
	})

	t.Run("Sign surrounding Attestation, should error", func(t *testing.T) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
		setupBaseStorage(t, req)

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)
		require.NoError(t, updateWithBasicHighestAtt(req.Storage))

		// first attestation
		req.Data = basicAttestationData()
		_, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)

		// add another attestation building on the base
		// 77 <- 78 <- 79
		att := &phase0.AttestationData{
			Slot:            284116,
			Index:           2,
			BeaconBlockRoot: _byteArray32("7b5679277ca45ea74e1deebc9d3e8c0e7d6c570b3cfaf6884be144a81dac9a0e"),
			Source: &phase0.Checkpoint{
				Epoch: 78,
				Root:  _byteArray32("7402fdc1ce16d449d637c34a172b349a12b2bae8d6d77e401006594d8057c33d"),
			},
			Target: &phase0.Checkpoint{
				Epoch: 79,
				Root:  _byteArray32("17959acc370274756fa5e9fdd7e7adf17204f49cc8457e49438c42c4883cbfb0"),
			},
		}
		domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")
		pubKey := _byteArray("95087182937f6982ae99f9b06bd116f463f414513032e33a3d175d9662eddf162101fcf6ca2a9fedaded74b8047c5dcf")
		req.Data = reqObject(att, domain, pubKey)
		_, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)

		// surround previous vote
		// 77 <- 78 <- 79
		// 	<------------ 80
		// slashable
		att.Slot = 284117
		att.Source.Epoch = 77
		att.Target.Epoch = 80
		req.Data = reqObject(att, domain, pubKey)
		res, err := b.HandleRequest(context.Background(), req)
		require.Error(t, err)
		require.EqualError(t, err, "failed to sign: slashable attestation (HighestAttestationVote), not signing")
		require.Nil(t, res)
	})

	t.Run("Sign surrounded Attestation, should error", func(t *testing.T) {
		req := logical.TestRequest(t, logical.CreateOperation, "accounts/sign")
		setupBaseStorage(t, req)

		// setup storage
		err := setupStorageWithWalletAndAccounts(req.Storage)
		require.NoError(t, err)
		require.NoError(t, updateWithBasicHighestAtt(req.Storage))

		// first attestation
		req.Data = basicAttestationData()
		_, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)

		// add another attestation building on the base
		// 77 <- 78 <- 79 <----------------------90
		att := &phase0.AttestationData{
			Slot:            284116,
			Index:           2,
			BeaconBlockRoot: _byteArray32("7b5679277ca45ea74e1deebc9d3e8c0e7d6c570b3cfaf6884be144a81dac9a0e"),
			Source: &phase0.Checkpoint{
				Epoch: 79,
				Root:  _byteArray32("7402fdc1ce16d449d637c34a172b349a12b2bae8d6d77e401006594d8057c33d"),
			},
			Target: &phase0.Checkpoint{
				Epoch: 95,
				Root:  _byteArray32("17959acc370274756fa5e9fdd7e7adf17204f49cc8457e49438c42c4883cbfb0"),
			},
		}
		domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")
		pubKey := _byteArray("95087182937f6982ae99f9b06bd116f463f414513032e33a3d175d9662eddf162101fcf6ca2a9fedaded74b8047c5dcf")
		req.Data = reqObject(att, domain, pubKey)
		_, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)

		// surround previous vote
		// 77 <- 78 <- 79 <----------------------95
		// 								88 <- 89
		// slashable
		att.Slot = 284117
		att.Source.Epoch = 89
		att.Target.Epoch = 88
		req.Data = reqObject(att, domain, pubKey)
		res, err := b.HandleRequest(context.Background(), req)
		require.Error(t, err)
		require.EqualError(t, err, "failed to sign: slashable attestation (HighestAttestationVote), not signing")
		require.Nil(t, res)
	})
}
