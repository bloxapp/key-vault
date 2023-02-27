package backend

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	vault "github.com/bloxapp/eth2-key-manager"
	"github.com/bloxapp/eth2-key-manager/signer"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"

	"github.com/bloxapp/key-vault/backend/store"
	"github.com/bloxapp/key-vault/keymanager/models"
)

// Endpoints patterns
const (
	// SignVoluntaryExitPattern is the path pattern for sign voluntary exit endpoint
	SignVoluntaryExitPattern = "accounts/sign-voluntary-exit"
)

func signsVoluntaryExitPath(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern:         SignVoluntaryExitPattern,
			HelpSynopsis:    "Sign voluntary exit",
			HelpDescription: `Sign voluntary exit`,
			Fields: map[string]*framework.FieldSchema{
				"sign_req": {
					Type:        framework.TypeString,
					Description: "SSZ Serialized sign voluntary exit request object",
					Default:     "",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathSignVoluntaryExit,
				},
			},
		},
	}
}

func (b *backend) pathSignVoluntaryExit(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Load config
	config, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get config")
	}

	// Parse request data
	reqEncoded := data.Get("sign_req").(string)
	reqByts, err := hex.DecodeString(reqEncoded)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode sign request hex")
	}

	signReq := &models.SignRequest{}
	if err := b.encoder.Decode(reqByts, signReq); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal sign request")
	}

	var resp map[string]interface{}
	err = b.lock(signReq.GetPublicKey(), func() error {
		// bring up KeyVault and wallet
		storage := store.NewHashicorpVaultStore(ctx, req.Storage, config.Network)
		options := vault.KeyVaultOptions{}
		options.SetStorage(storage)

		// Open wallet
		kv, err := vault.OpenKeyVault(&options)
		if err != nil {
			return errors.Wrap(err, "failed to open key vault")
		}

		wallet, err := kv.Wallet()
		if err != nil {
			return errors.Wrap(err, "failed to retrieve wallet")
		}

		var (
			simpleSigner signer.ValidatorSigner = signer.NewSimpleSigner(wallet, nil, storage.Network())
			sigErr       error
		)

		t, ok := signReq.GetObject().(*models.SignRequestVoluntaryExit)
		if !ok {
			return errors.New("failed to cast to sign request voluntary exit")
		}
		sig, _, sigErr := simpleSigner.SignVoluntaryExit(t.VoluntaryExit, signReq.SignatureDomain, signReq.PublicKey)
		signReqVoluntaryExit := &phase0.SignedVoluntaryExit{
			Message: t.VoluntaryExit,
		}
		copy(signReqVoluntaryExit.Signature[:], sig)

		marshalJSON, err := signReqVoluntaryExit.MarshalJSON()
		if err != nil {
			return errors.Wrap(err, "failed to marshal signed voluntary exit")
		}
		err = json.Unmarshal(marshalJSON, &resp)
		if err != nil {
			return errors.Wrap(err, "failed to unmarshal signed voluntary exit")
		}

		return sigErr
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign")
	}

	return &logical.Response{
		Data: resp,
	}, nil
}
