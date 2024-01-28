package tests

import (
	"encoding/hex"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/attestantio/go-eth2-client/api"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/utils/encoder"

	"github.com/bloxapp/key-vault/e2e"
	"github.com/bloxapp/key-vault/e2e/shared"
	"github.com/bloxapp/key-vault/keymanager/models"
)

// ProposalConcurrentSigning tests signing method concurrently.
type ProposalConcurrentSigning struct {
}

// Name returns the name of the test.
func (test *ProposalConcurrentSigning) Name() string {
	return "Test proposal concurrent signing"
}

// Run runs the test.
func (test *ProposalConcurrentSigning) Run(t *testing.T) {
	setup := e2e.Setup(t)

	// setup vault with db
	store := setup.UpdateStorage(t, core.PraterNetwork, true, core.HDWallet, nil)
	account := shared.RetrieveAccount(t, store)
	pubKey := account.ValidatorPublicKey()

	// Send requests in parallel
	wg := &sync.WaitGroup{}
	signedCnt := int64(0)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		t.Run("concurrent signing "+strconv.Itoa(i), func(t *testing.T) {
			go test.runSlashableProposal(t, &signedCnt, wg, setup, pubKey)
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, signedCnt)
}

// will return no error if trying to sign a slashable attestation will not work
func (test *ProposalConcurrentSigning) runSlashableProposal(t *testing.T, cnt *int64, wg *sync.WaitGroup, setup *e2e.BaseSetup, pubKey []byte) {
	defer wg.Done()

	blk := referenceBlock(t)
	blk.Phase0.ParentRoot = _byteArray32("7b5679277ca45ea74e1deebc9d3e8c0e7d6c570b3cfaf6884be144a81dac9a0d")
	domain := _byteArray32("01000000f071c66c6561d0b939feb15f513a019d99a84bd85635221e3ad42dac")
	req, err := test.serializedReq(pubKey, nil, domain, blk)
	require.NoError(t, err)

	_, err = setup.Sign("sign", req, core.PraterNetwork)
	if err == nil {
		atomic.AddInt64(cnt, 1)
	}
}

func (test *ProposalConcurrentSigning) serializedReq(pk, root []byte, domain [32]byte, blk *api.VersionedProposal) (map[string]interface{}, error) {
	req := &models.SignRequest{
		PublicKey:       pk,
		SigningRoot:     root,
		SignatureDomain: domain,
		Object:          &models.SignRequestBlock{VersionedBeaconBlock: blk},
	}

	byts, err := encoder.New().Encode(req)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"sign_req": hex.EncodeToString(byts),
	}, nil
}
