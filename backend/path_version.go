package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Endpoints patterns
const (
	// VersionPattern is the path pattern for version endpoint
	VersionPattern = "version"
)

func versionPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern:         VersionPattern,
			HelpSynopsis:    "Shows app version",
			HelpDescription: ``,
			Fields:          map[string]*framework.FieldSchema{},
			ExistenceCheck:  b.pathExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathVersion,
				},
			},
		},
	}
}

// pathVersion returns the current plugin version
func (b *backend) pathVersion(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			"version": b.Version,
		},
	}, nil
}
