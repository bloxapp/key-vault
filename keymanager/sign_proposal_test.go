package keymanager_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/keymanager"
	"github.com/bloxapp/key-vault/keymanager/models"
	"github.com/bloxapp/key-vault/utils/encoder"
)

func TestSignProposal(t *testing.T) {
	expectedSig := _byteArray("b75a751c2c5c16175c4678e8fc8ed75e903153b221f3803bf55982934113468139d91049d4c8f9efae92889505b42dda045df95e233d7ae0140f5bf882d91373a98056b09410769a7bc9319c9a42bc90c626a2301ba8f084522def59840aec80")

	var protect sync.Mutex
	var currentMethod http.HandlerFunc
	s := newTestRemoteWallet(func(writer http.ResponseWriter, request *http.Request) {
		currentMethod(writer, request)
	})
	defer s.Close()

	km, err := keymanager.NewKeyManager(logrus.NewEntry(logrus.New()), &keymanager.Config{
		Location:    s.URL,
		AccessToken: DefaultAccessToken,
		PubKey:      "a3862121db5914d7272b0b705e6e3c5336b79e316735661873566245207329c30f9a33d4fb5f5857fc6fd0a368186972",
		Network:     "prater",
	})
	require.NoError(t, err)

	runTest := func(t *testing.T, statusCode int, signature []byte, f func(wallet *keymanager.KeyManager)) {
		protect.Lock()
		currentMethod = func(writer http.ResponseWriter, request *http.Request) {
			require.Equal(t, http.MethodPost, request.Method)
			require.Equal(t, "/v1/ethereum/prater/accounts/sign", request.URL.Path)

			var reqBody map[string]interface{}
			require.NoError(t, json.NewDecoder(request.Body).Decode(&reqBody))

			// test un-marshaling the request
			val, ok := reqBody["sign_req"]
			require.True(t, ok)
			valByts, err := hex.DecodeString(val.(string))
			require.NoError(t, err)
			req := &models.SignRequest{}
			require.NoError(t, encoder.New().Decode(valByts, req))

			require.EqualValues(t, _byteArray("a3862121db5914d7272b0b705e6e3c5336b79e316735661873566245207329c30f9a33d4fb5f5857fc6fd0a368186972"), req.PublicKey)
			require.EqualValues(t, _byteArray32("0000000081509579e35e84020ad8751eca180b44df470332d3ad17fc6fd52459"), req.SignatureDomain)

			// root block
			actualRoot, err := req.Object.(*models.SignRequestBlock).VersionedBeaconBlock.Root()
			require.NoError(t, err)
			expectedRoot := _byteArray("c842b15864adc006334b251e1b692f21ae453a1524e8d2224d602a2822949190")
			require.EqualValues(t, expectedRoot, actualRoot[:])

			if statusCode == http.StatusOK {
				respBody := &logical.Response{
					Data: map[string]interface{}{
						"signature": hex.EncodeToString(signature),
					},
				}
				require.NoError(t, json.NewEncoder(writer).Encode(respBody))
			} else {
				writer.WriteHeader(statusCode)
			}
		}
		protect.Unlock()

		f(km)
	}

	t.Run("successfully signed data", func(t *testing.T) {
		runTest(t, http.StatusOK, expectedSig, func(km *keymanager.KeyManager) {
			actualSignature, err := km.Sign(context.Background(), testRequest(t))
			require.NoError(t, err)
			require.NotNil(t, actualSignature)
			require.EqualValues(t, expectedSig, actualSignature[:])
		})
	})

	t.Run("provide wrong pubKey", func(t *testing.T) {
		runTest(t, http.StatusOK, expectedSig, func(km *keymanager.KeyManager) {
			req := testRequest(t)
			req.PublicKey = _byteArray("a3862121db5914d7272b0b705e6e3c5336b79e316735661873566245207329c30f9a33d4fb5f5857fc6fd0a368186971")
			actualSignature, err := km.Sign(context.Background(), req)
			require.NotNil(t, err)
			require.True(t, keymanager.IsGenericError(err))
			require.EqualError(t, err, "{\"error\":\"no such key\"}")
			require.EqualValues(t, phase0.BLSSignature{}, actualSignature)
		})
	})

	//t.Run("rejects with denied", func(t *testing.T) {
	//	runTest(t, http.StatusUnauthorized, []byte(expectedSig), func(wallet *keymanager.KeyManager) {
	//		actualSignature, err := wallet.Sign(context.Background(), testRequest(t))
	//		require.True(t, keymanager.IsGenericError(err))
	//		require.Nil(t, actualSignature)
	//	})
	//})

	//t.Run("rejects with failed", func(t *testing.T) {
	//	runTest(t, http.StatusInternalServerError, []byte(actualSignature), func(wallet *keymanager.KeyManager) {
	//		actualSignature, err := wallet.SignProposal(domain, data)
	//		require.True(t, keymanager.IsGenericError(err))
	//		require.Nil(t, actualSignature)
	//	})
	//})
	//
	//t.Run("rejects with invalid signature", func(t *testing.T) {
	//	runTest(t, http.StatusOK, []byte("invalid"), func(wallet *keymanager.KeyManager) {
	//		actualSignature, err := wallet.SignProposal(domain, data)
	//		require.True(t, keymanager.IsGenericError(err))
	//		require.Nil(t, actualSignature)
	//	})
	//})
}

func testRequest(t *testing.T) *models.SignRequest {
	// block
	blkByts := _byteArray("010000000000000055000000000000003a43a4bf26fb5947e809c1f24f7dc6857c8ac007e535d48e6e4eca2122fd776badd5cb7e6a4bffd8ce7fe9697aed511661861e312ad546dcf5480159698f47a554000000a2c156a4bc9439f1d85f922f2abaa96e830f1c526101211bdb7d16f4ad9490a0302fc5adb089c05b5f16fd465962f47c04fc2b81a94d135a07c1613db61511c17284b51fafab984e56d3411e16e45f5068f146d9412f91d31ab0f237eac3d745a4e544482366bc9d5386f1cd0c4bf837327605620bf40c5514d51dfcadd14a4a8000000000000000a4e544482366bc9d5386f1cd0c4bf837327605620bf40c5514d51dfcadd14a4a0000000000000000000000000000000000000000000000000000000000000000dc000000dc000000dc000000c5010000c501000004000000e4000000000000000000000000000000000000003a43a4bf26fb5947e809c1f24f7dc6857c8ac007e535d48e6e4eca2122fd776b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003a43a4bf26fb5947e809c1f24f7dc6857c8ac007e535d48e6e4eca2122fd776b97b6f271ac364b041cd465f32fa7ffa19f5a811f1e6e14713f93e06537ef827d382bac72f0990b84f83cd9bbe0062815020086bf27b9ced172cc6add8ba5197991cf634d18666f5d43df6f09180ce20a357e4d05b2784409e32147f1042986e31f")
	blk := &phase0.BeaconBlock{}
	require.NoError(t, blk.UnmarshalSSZ(blkByts))

	// build request
	return &models.SignRequest{
		PublicKey:       _byteArray("a3862121db5914d7272b0b705e6e3c5336b79e316735661873566245207329c30f9a33d4fb5f5857fc6fd0a368186972"),
		SigningRoot:     nil,
		SignatureDomain: _byteArray32("0000000081509579e35e84020ad8751eca180b44df470332d3ad17fc6fd52459"),
		Object: &models.SignRequestBlock{VersionedBeaconBlock: &api.VersionedProposal{
			Phase0:  blk,
			Version: spec.DataVersionPhase0,
		}},
	}
}
