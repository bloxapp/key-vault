package keymanager

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/bloxapp/key-vault/backend"
	"github.com/bloxapp/key-vault/keymanager/models"
	"github.com/bloxapp/key-vault/utils/bytex"
	"github.com/bloxapp/key-vault/utils/encoder"
	"github.com/bloxapp/key-vault/utils/endpoint"
	"github.com/bloxapp/key-vault/utils/httpex"
)

// Predefined errors
var (
	ErrLocationMissing    = NewGenericErrorMessage("wallet location is required")
	ErrTokenMissing       = NewGenericErrorMessage("wallet access token is required")
	ErrPubKeyMissing      = NewGenericErrorMessage("wallet public key is required")
	ErrUnsupportedSigning = NewGenericErrorWithMessage("remote HTTP key manager does not support such signing method")
	ErrNoSuchKey          = NewGenericErrorWithMessage("no such key")
)

// IkeyManager interface contains functions from prysm kv
type IkeyManager interface {
	FetchValidatingPublicKeys(_ context.Context) ([][48]byte, error)
	FetchAllValidatingPublicKeys(_ context.Context) ([][48]byte, error)
	Sign(_ context.Context, req *models.SignRequest) (phase0.BLSSignature, error)
	sendRequest(_ context.Context, method, path string, reqBody interface{}, respBody interface{}) error
}

// KeyManager is a key manager that accesses a remote vault wallet daemon through HTTP connection.
type KeyManager struct {
	remoteAddress string
	accessToken   string
	originPubKey  string
	pubKey        [48]byte
	network       string
	httpClient    *http.Client
	encoder       encoder.IEncoder

	log *logrus.Entry
}

var _ IkeyManager = (*KeyManager)(nil)

// NewKeyManager is the constructor of KeyManager.
func NewKeyManager(log *logrus.Entry, opts *Config) (*KeyManager, error) {
	if len(opts.Location) == 0 {
		return nil, ErrLocationMissing
	}
	if len(opts.AccessToken) == 0 {
		return nil, ErrTokenMissing
	}
	if len(opts.PubKey) == 0 {
		return nil, ErrPubKeyMissing
	}

	// Decode public key
	decodedPubKey, err := hex.DecodeString(opts.PubKey)
	if err != nil {
		return nil, NewGenericError(err, "failed to hex decode public key '%s'", opts.PubKey)
	}

	log.Logf(logrus.InfoLevel, "KeyManager initialing for %s network", opts.Network)

	return &KeyManager{
		remoteAddress: opts.Location,
		accessToken:   opts.AccessToken,
		originPubKey:  opts.PubKey,
		pubKey:        bytex.ToBytes48(decodedPubKey),
		network:       opts.Network,
		encoder:       encoder.New(),
		httpClient: httpex.CreateClient(log, func(resp *http.Response, err error, numTries int) (*http.Response, error) {
			if err == nil {
				return resp, nil
			}

			fields := logrus.Fields{}
			if resp != nil {
				fields["status_code"] = resp.StatusCode

				if resp.Body != nil {
					defer resp.Body.Close()

					respBody, err := io.ReadAll(resp.Body)
					if err != nil {
						return resp, err
					}
					fields["response_body"] = string(respBody)
				}
			}
			log.WithError(err).WithFields(fields).Error("failed to send request to key manager")
			return resp, errors.Errorf("giving up after %d attempt(s): %s", numTries, err)
		}),
		log: log,
	}, nil
}

// FetchValidatingPublicKeys implements KeyManager-v2 interface.
func (km *KeyManager) FetchValidatingPublicKeys(_ context.Context) ([][48]byte, error) {
	return [][48]byte{km.pubKey}, nil
}

// FetchAllValidatingPublicKeys implements KeyManager-v2 interface.
func (km *KeyManager) FetchAllValidatingPublicKeys(_ context.Context) ([][48]byte, error) {
	return [][48]byte{km.pubKey}, nil
}

// Sign implements IKeymanager interface.
func (km *KeyManager) Sign(ctx context.Context, req *models.SignRequest) (phase0.BLSSignature, error) {
	if bytex.ToBytes48(req.GetPublicKey()) != km.pubKey {
		return phase0.BLSSignature{}, ErrNoSuchKey
	}

	byts, err := km.encoder.Encode(req)
	if err != nil {
		return phase0.BLSSignature{}, errors.Wrap(err, "failed to encode request")
	}
	reqMap := map[string]interface{}{
		"sign_req": hex.EncodeToString(byts),
	}

	var resp models.SignResponse
	if err := km.sendRequest(ctx, http.MethodPost, backend.SignPattern, reqMap, &resp); err != nil {
		return phase0.BLSSignature{}, err
	}

	// Signature is base64 encoded, so we have to decode that.
	decodedSignature, err := hex.DecodeString(resp.Data.Signature)
	if err != nil {
		return phase0.BLSSignature{}, NewGenericError(err, "failed to base64 decode")
	}

	var signature phase0.BLSSignature
	copy(signature[:], decodedSignature)
	return signature, nil
}

// sendRequest implements the logic to work with HTTP requests.
func (km *KeyManager) sendRequest(ctx context.Context, method, path string, reqBody interface{}, respBody interface{}) error {
	networkPath, err := endpoint.Build(km.network, path)
	if err != nil {
		return NewGenericError(err, "could not build network path")
	}
	endpointStr := km.remoteAddress + networkPath

	payloadByts, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	// Prepare a new request
	req, err := http.NewRequestWithContext(ctx, method, endpointStr, bytes.NewBuffer(payloadByts))
	if err != nil {
		return NewGenericError(err, "failed to create HTTP request")
	}

	// Pass auth token.
	req.Header.Set("Authorization", "Bearer "+km.accessToken)
	req.Header.Set("Content-Type", "application/json")

	// Send request.
	resp, err := km.httpClient.Do(req)
	if err != nil {
		return NewGenericError(err, "failed to send HTTP request")
	}
	defer resp.Body.Close()

	// Check status code. Must be 200.
	if resp.StatusCode != http.StatusOK {
		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			km.log.WithError(err).Error("failed to read error response body")
		}

		return NewHTTPRequestError(endpointStr, resp.StatusCode, responseBody, "unexpected status code")
	}

	// Read response body into the given object.
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return NewGenericError(err, "failed to decode response body")
	}

	return nil
}
