package encoder

import (
	"errors"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"

	"github.com/bloxapp/key-vault/keymanager/models"
)

// V2 encoder
type V2 struct {
}

// New return v2 struct
func New() *V2 {
	return &V2{}
}

// Encode to ssz format
func (l *V2) Encode(obj interface{}) ([]byte, error) {
	switch t := obj.(type) {
	case *phase0.AttestationData:
		return t.MarshalSSZ()
	case phase0.Slot:
		return ssz.MarshalUint64(nil, uint64(t)), nil
	case *models.SignRequest:
		return encodeSignRequest(t)
	}
	return nil, errors.New("type not supported")
}

// Decode to ssz format
func (l *V2) Decode(data []byte, v interface{}) error {
	switch t := v.(type) {
	case *phase0.AttestationData:
		return t.UnmarshalSSZ(data)
	case *models.SignRequest:
		return decodeSignRequest(data, t)
	}
	return errors.New("type not supported")
}
