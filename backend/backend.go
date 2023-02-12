package backend

import (
	"context"
	"encoding/hex"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/bloxapp/key-vault/utils/encoder"
)

// Factory returns the backend factory
func Factory(version string, logger *logrus.Logger) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b := newBackend(version, logger)
		if err := b.Setup(ctx, conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

// newBackend returns the backend
func newBackend(version string, logger *logrus.Logger) *backend {
	b := &backend{
		logger:      logger,
		Version:     version,
		signMapLock: &sync.Mutex{},
		signLock:    make(map[string]*sync.Mutex),
		encoder:     encoder.New(),
	}
	b.Backend = &framework.Backend{
		Help: "",
		Paths: framework.PathAppend(
			versionPaths(b),
			storagePaths(b),
			storageSlashingDataPaths(b),
			accountsPaths(b),
			signsPaths(b),
			configPaths(b),
		),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"wallet/",
			},
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
	}
	return b
}

// backend implements the Backend for this plugin
type backend struct {
	*framework.Backend
	logger      *logrus.Logger
	Version     string
	signMapLock *sync.Mutex
	signLock    map[string]*sync.Mutex
	encoder     encoder.IEncoder
}

// pathExistenceCheck checks if the given path exists
func (b *backend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		b.logger.WithError(err).Error("Path existence check failed")
		return false, errors.Errorf("existence check failed: %v", err)
	}

	if b.Route(req.Path) == nil {
		b.logger.WithField("path", hex.EncodeToString(out.Value)).Error("Path not found")
		return false, errors.Errorf("existence check failed: %s", hex.EncodeToString(out.Value))
	}

	return out != nil, nil
}
