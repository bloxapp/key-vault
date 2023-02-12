package models

// SignRequestSyncCommitteeMessage struct for sign req committiee msg
type SignRequestSyncCommitteeMessage struct {
	Root SSZBytes
}

// isSignRequestObject implement interface func
func (m *SignRequestSyncCommitteeMessage) isSignRequestObject() {}
