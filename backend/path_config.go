package backend

import (
	"context"
	"encoding/json"

	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

var (
	// BLSPubkeyLength is the length of a BLS public key.
	BLSPubkeyLength = 48
	// FeeRecipientLength is the length of a fee recipient address.
	FeeRecipientLength = 20
)

// Endpoints patterns
const (
	// ConfigPattern is the path pattern for config endpoint
	ConfigPattern = "config"
)

// Config contains the configuration for each mount
type Config struct {
	Network       core.Network  `json:"network"`
	FeeRecipients FeeRecipients `json:"fee_recipients"`
}

// Map returns a map representation of the FeeRecipients.
func (c Config) Map() map[string]interface{} {
	return map[string]interface{}{
		"network":        c.Network,
		"fee_recipients": c.FeeRecipients,
	}
}

func configPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: ConfigPattern,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathWriteConfig,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathWriteConfig,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathReadConfig,
				},
			},
			HelpSynopsis:    "Configure the Vault Ethereum plugin.",
			HelpDescription: "Configure the Vault Ethereum plugin.",
			Fields: map[string]*framework.FieldSchema{
				"network": {
					Type: framework.TypeString,
					Description: `Ethereum network - can be one of the following values:
					mainnet - MainNet Network
					prater - Prater Test Network`,
					AllowedValues: []interface{}{
						string(core.PraterNetwork),
						string(core.MainNetwork),
					},
				},
				"fee_recipients": {
					Type:        framework.TypeMap,
					Description: `Validator pubic keys and their associated fee recipient addresses.`,
				},
			},
		},
	}
}

// pathWriteConfig is the write config path handler
func (b *backend) pathWriteConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	network := core.NetworkFromString(data.Get("network").(string))
	if network == "" {
		return nil, errors.New("invalid network provided")
	}

	configBundle := Config{
		Network: network,
	}

	// Parse and validate the fee recipients (if given.)
	if data, ok := data.Get("fee_recipients").(map[string]interface{}); ok {
		recipients, err := ParseFeeRecipients(data)
		if err != nil {
			return nil, err
		}
		configBundle.FeeRecipients = recipients
	}

	// Create storage entry
	entry, err := logical.StorageEntryJSON("config", configBundle.Map())
	if err != nil {
		return nil, err
	}

	// Store config
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Return the secret
	return &logical.Response{
		Data: configBundle.Map(),
	}, nil
}

// pathReadConfig is the read config path handler
func (b *backend) pathReadConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configBundle, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if configBundle == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: configBundle.Map(),
	}, nil
}

// readConfig returns the configuration for this PluginBackend.
func (b *backend) readConfig(ctx context.Context, s logical.Storage) (*Config, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, errors.New("the plugin has not been configured yet")
	}

	var result Config
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, errors.Wrap(err, "error reading configuration")
	}

	return &result, nil
}

// FeeRecipients is a map of validator public keys and their associated fee recipient addresses.
// Both the public key and the address are 0x-prefixed hex strings.
type FeeRecipients map[string]string

// ParseFeeRecipients parses & validates the fee recipients from a given map[string]interface{}
func ParseFeeRecipients(input map[string]interface{}) (FeeRecipients, error) {
	feeRecipients := FeeRecipients{}
	for key, value := range input {
		// Decode and validate the validator key,
		var normalizedKey string
		switch key {
		case "default":
			normalizedKey = "default"
		default:
			validatorPubkey, err := hexutil.Decode(key)
			if err != nil || len(validatorPubkey) != BLSPubkeyLength {
				return nil, errors.Wrap(err, "invalid fee_recipients provided")
			}
			normalizedKey = hexutil.Encode(validatorPubkey)
		}

		// Decode and validate the fee recipient address.
		recipientAddrStr, _ := value.(string)
		recipientAddr, err := hexutil.Decode(recipientAddrStr)
		if err != nil || len(recipientAddr) != FeeRecipientLength {
			return nil, errors.Wrap(err, "invalid fee_recipients provided")
		}

		feeRecipients[normalizedKey] = hexutil.Encode(recipientAddr)
	}
	return feeRecipients, nil
}

// UnmarshalJSON decodes JSON-encoded FeeRecipients with validation.
func (f *FeeRecipients) UnmarshalJSON(data []byte) error {
	var input map[string]interface{}
	if err := json.Unmarshal(data, &input); err != nil {
		return err
	}
	feeRecipients, err := ParseFeeRecipients(input)
	if err != nil {
		return err
	}
	*f = feeRecipients
	return nil
}

// Default returns the default fee recipient.
func (f FeeRecipients) Default() (common.Address, bool) {
	if f["default"] == "" {
		return common.Address{}, false
	}
	return common.HexToAddress(f["default"]), true
}

// Get returns the fee recipient for the given public key.
func (f FeeRecipients) Get(pubKey []byte) (common.Address, bool) {
	pubKeyHex := hexutil.Encode(pubKey)
	if f[pubKeyHex] == "" {
		return f.Default()
	}
	return common.HexToAddress(f[pubKeyHex]), true
}
