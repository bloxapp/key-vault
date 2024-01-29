package encoder

import (
	"encoding/json"
	"reflect"

	"github.com/attestantio/go-eth2-client/api"
	eth2apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	apiv1bellatrix "github.com/attestantio/go-eth2-client/api/v1/bellatrix"
	apiv1capella "github.com/attestantio/go-eth2-client/api/v1/capella"
	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/pkg/errors"

	"github.com/bloxapp/key-vault/keymanager/models"
)

type signRequestEncoded struct {
	PublicKey       []byte   `json:"public_key,omitempty"`
	SigningRoot     []byte   `json:"signing_root,omitempty"`
	SignatureDomain [32]byte `json:"signature_domain,omitempty"`
	Data            []byte
	ObjectType      string
	// Used for block/registration versioning (altair, etc.)
	Version uint64
}

func encodeSignRequest(sr *models.SignRequest) ([]byte, error) {
	toEncode := signRequestEncoded{
		PublicKey:       sr.PublicKey,
		SigningRoot:     sr.SigningRoot,
		SignatureDomain: sr.SignatureDomain,
	}

	if sr.Object == nil {
		return json.Marshal(toEncode)
	}

	switch t := sr.Object.(type) {
	case *models.SignRequestAttestationData:
		byts, err := t.AttestationData.MarshalSSZ()
		if err != nil {
			return nil, err
		}
		toEncode.Data = byts
		toEncode.ObjectType = reflect.TypeOf(t).String()
	case *models.SignRequestBlock:
		var byts []byte
		var err error
		switch t.VersionedBeaconBlock.Version {
		case spec.DataVersionPhase0:
			if t.VersionedBeaconBlock.Phase0 == nil {
				return nil, errors.New("no phase0 block")
			}
			byts, err = t.VersionedBeaconBlock.Phase0.MarshalSSZ()
		case spec.DataVersionAltair:
			if t.VersionedBeaconBlock.Altair == nil {
				return nil, errors.New("no altair block")
			}
			byts, err = t.VersionedBeaconBlock.Altair.MarshalSSZ()
		case spec.DataVersionBellatrix:
			if t.VersionedBeaconBlock.Bellatrix == nil {
				return nil, errors.New("no bellatrix block")
			}
			byts, err = t.VersionedBeaconBlock.Bellatrix.MarshalSSZ()
		case spec.DataVersionCapella:
			if t.VersionedBeaconBlock.Capella == nil {
				return nil, errors.New("no capella block")
			}
			byts, err = t.VersionedBeaconBlock.Capella.MarshalSSZ()
		case spec.DataVersionDeneb:
			if t.VersionedBeaconBlock.Deneb == nil {
				return nil, errors.New("no deneb block")
			}
			byts, err = t.VersionedBeaconBlock.Deneb.MarshalSSZ()
		default:
			return nil, errors.Errorf("unsupported block version %d", t.VersionedBeaconBlock.Version)
		}

		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal block")
		}
		toEncode.Data = byts
		toEncode.ObjectType = reflect.TypeOf(t).String()
		toEncode.Version = uint64(t.VersionedBeaconBlock.Version)
	case *models.SignRequestBlindedBlock:
		var byts []byte
		var err error
		switch t.VersionedBlindedBeaconBlock.Version {
		case spec.DataVersionBellatrix:
			if t.VersionedBlindedBeaconBlock.Bellatrix == nil {
				return nil, errors.New("no bellatrix blinded block")
			}
			byts, err = t.VersionedBlindedBeaconBlock.Bellatrix.MarshalSSZ()
		case spec.DataVersionCapella:
			if t.VersionedBlindedBeaconBlock.Capella == nil {
				return nil, errors.New("no capella blinded block")
			}
			byts, err = t.VersionedBlindedBeaconBlock.Capella.MarshalSSZ()
		case spec.DataVersionDeneb:
			if t.VersionedBlindedBeaconBlock.Deneb == nil {
				return nil, errors.New("no deneb blinded block")
			}
			byts, err = t.VersionedBlindedBeaconBlock.Deneb.MarshalSSZ()
		default:
			return nil, errors.Errorf("unsupported blinded block version %d", t.VersionedBlindedBeaconBlock.Version)
		}

		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal blinded block")
		}
		toEncode.Data = byts
		toEncode.ObjectType = reflect.TypeOf(t).String()
		toEncode.Version = uint64(t.VersionedBlindedBeaconBlock.Version)
	case *models.SignRequestAggregateAttestationAndProof:
		byts, err := t.AggregateAttestationAndProof.MarshalSSZ()
		if err != nil {
			return nil, err
		}
		toEncode.Data = byts
		toEncode.ObjectType = reflect.TypeOf(t).String()

		ddd := &phase0.AggregateAndProof{}
		if err := ddd.UnmarshalSSZ(byts); err != nil {
			return nil, err
		}
	case *models.SignRequestEpoch:
		var byts []byte
		toEncode.Data = ssz.MarshalUint64(byts, uint64(t.Epoch))
		toEncode.ObjectType = reflect.TypeOf(t).String()
	case *models.SignRequestSlot:
		var byts []byte
		toEncode.Data = ssz.MarshalUint64(byts, uint64(t.Slot))
		toEncode.ObjectType = reflect.TypeOf(t).String()
	case *models.SignRequestSyncCommitteeMessage:
		toEncode.Data = t.Root
		toEncode.ObjectType = reflect.TypeOf(t).String()
	case *models.SignRequestSyncAggregatorSelectionData:
		byts, err := t.SyncAggregatorSelectionData.MarshalSSZ()
		if err != nil {
			return nil, err
		}
		toEncode.Data = byts
		toEncode.ObjectType = reflect.TypeOf(t).String()
	case *models.SignRequestContributionAndProof:
		byts, err := t.ContributionAndProof.MarshalSSZ()
		if err != nil {
			return nil, err
		}
		toEncode.Data = byts
		toEncode.ObjectType = reflect.TypeOf(t).String()
	case *models.SignRequestRegistration:
		var byts []byte
		var err error
		switch t.VersionedValidatorRegistration.Version {
		case spec.BuilderVersionV1:
			if t.VersionedValidatorRegistration.V1 == nil {
				return nil, errors.New("no validator registration")
			}
			byts, err = t.VersionedValidatorRegistration.V1.MarshalSSZ()
		default:
			return nil, errors.Errorf("unsupported registration version %d", t.VersionedValidatorRegistration.Version)
		}

		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal validator registration")
		}
		toEncode.Data = byts
		toEncode.ObjectType = reflect.TypeOf(t).String()
		toEncode.Version = uint64(t.VersionedValidatorRegistration.Version)
	case *models.SignRequestVoluntaryExit:
		byts, err := t.VoluntaryExit.MarshalSSZ()
		if err != nil {
			return nil, err
		}
		toEncode.Data = byts
		toEncode.ObjectType = reflect.TypeOf(t).String()
	default:
		return nil, errors.New("sign request unknown object type")
	}

	return json.Marshal(toEncode)
}

func decodeSignRequest(data []byte, sr *models.SignRequest) error {
	toDecode := &signRequestEncoded{}
	if err := json.Unmarshal(data, toDecode); err != nil {
		return err
	}

	sr.PublicKey = toDecode.PublicKey
	sr.SignatureDomain = toDecode.SignatureDomain
	sr.SigningRoot = toDecode.SigningRoot

	if toDecode.Data == nil {
		return nil
	}

	switch toDecode.ObjectType {
	case "*models.SignRequestAttestationData":
		data := &phase0.AttestationData{}
		if err := data.UnmarshalSSZ(toDecode.Data); err != nil {
			return err
		}
		sr.Object = &models.SignRequestAttestationData{AttestationData: data}
	case "*models.SignRequestBlock":
		data := &spec.VersionedBeaconBlock{}

		switch spec.DataVersion(toDecode.Version) {
		case spec.DataVersionPhase0:
			var blk phase0.BeaconBlock
			if err := blk.UnmarshalSSZ(toDecode.Data); err != nil {
				return err
			}
			data.Version = spec.DataVersionPhase0
			data.Phase0 = &blk
		case spec.DataVersionAltair:
			var blk altair.BeaconBlock
			if err := blk.UnmarshalSSZ(toDecode.Data); err != nil {
				return err
			}
			data.Version = spec.DataVersionAltair
			data.Altair = &blk
		case spec.DataVersionBellatrix:
			var blk bellatrix.BeaconBlock
			if err := blk.UnmarshalSSZ(toDecode.Data); err != nil {
				return err
			}
			data.Version = spec.DataVersionBellatrix
			data.Bellatrix = &blk
		case spec.DataVersionCapella:
			var blk capella.BeaconBlock
			if err := blk.UnmarshalSSZ(toDecode.Data); err != nil {
				return err
			}
			data.Version = spec.DataVersionCapella
			data.Capella = &blk
		case spec.DataVersionDeneb:
			var blk deneb.BeaconBlock
			if err := blk.UnmarshalSSZ(toDecode.Data); err != nil {
				return err
			}
			data.Version = spec.DataVersionDeneb
			data.Deneb = &blk
		default:
			return errors.Errorf("unsupported block version %d", toDecode.Version)
		}

		sr.Object = &models.SignRequestBlock{VersionedBeaconBlock: data}
	case "*models.SignRequestBlindedBlock":
		data := &api.VersionedBlindedBeaconBlock{}

		switch spec.DataVersion(toDecode.Version) {
		case spec.DataVersionBellatrix:
			var blk apiv1bellatrix.BlindedBeaconBlock
			if err := blk.UnmarshalSSZ(toDecode.Data); err != nil {
				return err
			}
			data.Version = spec.DataVersionBellatrix
			data.Bellatrix = &blk
		case spec.DataVersionCapella:
			var blk apiv1capella.BlindedBeaconBlock
			if err := blk.UnmarshalSSZ(toDecode.Data); err != nil {
				return err
			}
			data.Version = spec.DataVersionCapella
			data.Capella = &blk
		case spec.DataVersionDeneb:
			var blk apiv1deneb.BlindedBeaconBlock
			if err := blk.UnmarshalSSZ(toDecode.Data); err != nil {
				return err
			}
			data.Version = spec.DataVersionDeneb
			data.Deneb = &blk
		default:
			return errors.Errorf("unsupported blinded block version %d", toDecode.Version)
		}

		sr.Object = &models.SignRequestBlindedBlock{VersionedBlindedBeaconBlock: data}
	case "*models.SignRequestSlot":
		slot := ssz.UnmarshallUint64(toDecode.Data)
		sr.Object = &models.SignRequestSlot{Slot: phase0.Slot(slot)}
	case "*models.SignRequestEpoch":
		epoch := ssz.UnmarshallUint64(toDecode.Data)
		sr.Object = &models.SignRequestEpoch{Epoch: phase0.Epoch(epoch)}
	case "*models.SignRequestAggregateAttestationAndProof":
		data := &phase0.AggregateAndProof{}
		if err := data.UnmarshalSSZ(toDecode.Data); err != nil {
			return err
		}
		sr.Object = &models.SignRequestAggregateAttestationAndProof{AggregateAttestationAndProof: data}
	case "*models.SignRequestSyncCommitteeMessage":
		sr.Object = &models.SignRequestSyncCommitteeMessage{Root: toDecode.Data}
	case "*models.SignRequestSyncAggregatorSelectionData":
		data := &altair.SyncAggregatorSelectionData{}
		if err := data.UnmarshalSSZ(toDecode.Data); err != nil {
			return err
		}
		sr.Object = &models.SignRequestSyncAggregatorSelectionData{SyncAggregatorSelectionData: data}
	case "*models.SignRequestContributionAndProof":
		data := &altair.ContributionAndProof{}
		if err := data.UnmarshalSSZ(toDecode.Data); err != nil {
			return err
		}
		sr.Object = &models.SignRequestContributionAndProof{ContributionAndProof: data}
	case "*models.SignRequestRegistration":
		data := &api.VersionedValidatorRegistration{}

		switch spec.BuilderVersion(toDecode.Version) {
		case spec.BuilderVersionV1:
			var reg eth2apiv1.ValidatorRegistration
			if err := reg.UnmarshalSSZ(toDecode.Data); err != nil {
				return err
			}
			data.Version = spec.BuilderVersionV1
			data.V1 = &reg
		default:
			return errors.Errorf("unsupported registration version %d", toDecode.Version)
		}

		sr.Object = &models.SignRequestRegistration{VersionedValidatorRegistration: data}
	case "*models.SignRequestVoluntaryExit":
		data := &phase0.VoluntaryExit{}
		if err := data.UnmarshalSSZ(toDecode.Data); err != nil {
			return err
		}
		sr.Object = &models.SignRequestVoluntaryExit{VoluntaryExit: data}
	default:
		return errors.New("sign request unknown object type")
	}
	return nil
}
