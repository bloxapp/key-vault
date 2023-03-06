package backend

import (
	"context"
	"encoding/hex"
	"sync"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	vault "github.com/bloxapp/eth2-key-manager"
	"github.com/bloxapp/eth2-key-manager/signer"
	slashingprotection "github.com/bloxapp/eth2-key-manager/slashing_protection"
	"github.com/ethereum/go-ethereum/common"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"

	"github.com/bloxapp/key-vault/backend/store"
	"github.com/bloxapp/key-vault/keymanager/models"
)

// Endpoints patterns
const (
	// SignAttestationPattern is the path pattern for sign attestation endpoint
	SignPattern = "accounts/sign"
)

func signsPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern:         SignPattern,
			HelpSynopsis:    "Sign",
			HelpDescription: `Sign`,
			Fields: map[string]*framework.FieldSchema{
				"sign_req": {
					Type:        framework.TypeString,
					Description: "SSZ Serialized sign request object",
					Default:     "",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathSign,
				},
			},
		},
	}
}

func (b *backend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

	var sig []byte
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
			protector                           = slashingprotection.NewNormalProtection(storage)
			simpleSigner signer.ValidatorSigner = signer.NewSimpleSigner(wallet, protector, storage.Network())
			sigErr       error
		)

		switch t := signReq.GetObject().(type) {
		case *models.SignRequestBlock:
			sig, _, sigErr = simpleSigner.SignBeaconBlock(t.VersionedBeaconBlock, signReq.SignatureDomain, signReq.PublicKey)
		case *models.SignRequestBlindedBlock:
			sig, _, sigErr = simpleSigner.SignBlindedBeaconBlock(t.VersionedBlindedBeaconBlock, signReq.SignatureDomain, signReq.PublicKey)
		case *models.SignRequestAttestationData:
			sig, _, sigErr = simpleSigner.SignBeaconAttestation(t.AttestationData, signReq.SignatureDomain, signReq.PublicKey)
		case *models.SignRequestSlot:
			sig, _, sigErr = simpleSigner.SignSlot(t.Slot, signReq.SignatureDomain, signReq.PublicKey)
		case *models.SignRequestEpoch:
			sig, _, sigErr = simpleSigner.SignEpoch(t.Epoch, signReq.SignatureDomain, signReq.PublicKey)
		case *models.SignRequestAggregateAttestationAndProof:
			sig, _, sigErr = simpleSigner.SignAggregateAndProof(t.AggregateAttestationAndProof, signReq.SignatureDomain, signReq.PublicKey)
		case *models.SignRequestSyncCommitteeMessage:
			sig, _, sigErr = simpleSigner.SignSyncCommittee(t.Root, signReq.SignatureDomain, signReq.PublicKey)
		case *models.SignRequestSyncAggregatorSelectionData:
			sig, _, sigErr = simpleSigner.SignSyncCommitteeSelectionData(t.SyncAggregatorSelectionData, signReq.SignatureDomain, signReq.PublicKey)
		case *models.SignRequestContributionAndProof:
			sig, _, sigErr = simpleSigner.SignSyncCommitteeContributionAndProof(t.ContributionAndProof, signReq.SignatureDomain, signReq.PublicKey)
		case *models.SignRequestRegistration:
			feeRecipient, err := t.VersionedValidatorRegistration.FeeRecipient()
			if err != nil {
				return errors.Wrap(err, "failed to get fee recipient")
			}
			validateErr := validateRequestedFeeRecipient(signReq.PublicKey, config.FeeRecipients, feeRecipient)
			if validateErr != nil {
				return errors.Wrap(validateErr, "refused to sign")
			}
			sig, _, sigErr = simpleSigner.SignRegistration(t.VersionedValidatorRegistration, signReq.SignatureDomain, signReq.PublicKey)
		default:
			return errors.New("sign request: not supported")
		}

		// Some tests rely on the error message returned by SignBeaconBlock,
		// so this error should not be wrapped!
		return sigErr
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": hex.EncodeToString(sig),
		},
	}, nil
}

func (b *backend) lock(pubKeyBytes []byte, cb func() error) error {
	lock := func() *sync.Mutex {
		b.signMapLock.Lock()
		defer b.signMapLock.Unlock()
		pubKey := hex.EncodeToString(pubKeyBytes)
		if _, ok := b.signLock[pubKey]; !ok {
			b.signLock[pubKey] = &sync.Mutex{}
		}
		return b.signLock[pubKey]
	}()

	lock.Lock()
	err := cb()
	lock.Unlock()

	return err
}

var (
	// ErrFeeRecipientNotSet is returned when the fee recipient isn't set.
	ErrFeeRecipientNotSet = errors.New("fee recipient is not configured for public key")

	// ErrFeeRecipientDiffers is returned when the fee recipient does not match the requested one.
	ErrFeeRecipientDiffers = errors.New("requested fee recipient does not match configured fee recipient")
)

func validateRequestedFeeRecipient(pubKey []byte, configFeeRecipients FeeRecipients, requestedFeeRecipient bellatrix.ExecutionAddress) error {
	feeRecipient, ok := configFeeRecipients.Get(pubKey)
	if !ok {
		return ErrFeeRecipientNotSet
	}
	if feeRecipient != common.BytesToAddress(requestedFeeRecipient[:]) {
		return ErrFeeRecipientDiffers
	}
	return nil
}
