package models

import (
	"github.com/attestantio/go-eth2-client/spec/altair"
)

// SignRequestSyncAggregatorSelectionData struct for sign req committiee msg
type SignRequestSyncAggregatorSelectionData struct {
	SyncAggregatorSelectionData *altair.SyncAggregatorSelectionData
}

// isSignRequestObject implement interface func
func (m *SignRequestSyncAggregatorSelectionData) isSignRequestObject() {}
