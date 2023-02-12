package models

import (
	"github.com/attestantio/go-eth2-client/api"
)

// SignRequestRegistration struct
type SignRequestRegistration struct {
	VersionedValidatorRegistration *api.VersionedValidatorRegistration
}

// isSignRequestObject implement func
func (m *SignRequestRegistration) isSignRequestObject() {}
