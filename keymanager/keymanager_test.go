package keymanager_test

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bloxapp/key-vault/keymanager/models"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/key-vault/keymanager"
	"github.com/bloxapp/key-vault/utils/bytex"
)

var (
	DefaultAccountPublicKey = "965586b5d05c851873f26cb736ed42de96591674772576e7b43848cd7a5c2827a5c5228034fdd55be0e9dc0f0cbc91d7"
	DefaultAccessToken      = "supersecureaccesstoken"
)

func TestNewKeyManager(t *testing.T) {
	entry := logrus.NewEntry(logrus.New())
	type args struct {
		log  *logrus.Entry
		opts *keymanager.Config
	}
	tests := []struct {
		name    string
		args    args
		want    *keymanager.KeyManager
		wantErr bool
	}{
		{
			name: "empty location",
			args: args{
				log: entry,
				opts: &keymanager.Config{
					AccessToken: "AccessToken",
					PubKey:      DefaultAccountPublicKey,
					Network:     "Network",
				},
			},
			wantErr: true,
		},
		{
			name: "empty access token",
			args: args{
				log: entry,
				opts: &keymanager.Config{
					Location: "Location",
					PubKey:   DefaultAccountPublicKey,
					Network:  "Network",
				},
			},
			wantErr: true,
		},
		{
			name: "empty public key",
			args: args{
				log: entry,
				opts: &keymanager.Config{
					Location:    "Location",
					AccessToken: "AccessToken",
					Network:     "Network",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid public key",
			args: args{
				log: entry,
				opts: &keymanager.Config{
					Location:    "Location",
					AccessToken: "AccessToken",
					PubKey:      "invalid",
					Network:     "Network",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := keymanager.NewKeyManager(tt.args.log, tt.args.opts)
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestKeyManager_FetchValidatingPublicKeys(t *testing.T) {
	entry := logrus.NewEntry(logrus.New())

	pubKey, err := hex.DecodeString(DefaultAccountPublicKey)
	require.NoError(t, err)

	type args struct {
		log  *logrus.Entry
		opts *keymanager.Config
	}
	tests := []struct {
		name    string
		args    args
		want    [][48]byte
		wantErr bool
	}{
		{
			name: "fetch all public keys",
			args: args{
				log: entry,
				opts: &keymanager.Config{
					Location:    "Location",
					AccessToken: DefaultAccessToken,
					PubKey:      DefaultAccountPublicKey,
					Network:     "Network",
				},
			},
			want: [][48]byte{bytex.ToBytes48(pubKey)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km, err := keymanager.NewKeyManager(tt.args.log, tt.args.opts)
			require.NoError(t, err)

			got, err := km.FetchValidatingPublicKeys(context.Background())
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestKeyManager_FetchAllValidatingPublicKeys(t *testing.T) {
	entry := logrus.NewEntry(logrus.New())

	pubKey, err := hex.DecodeString(DefaultAccountPublicKey)
	require.NoError(t, err)

	type args struct {
		log  *logrus.Entry
		opts *keymanager.Config
	}
	tests := []struct {
		name    string
		args    args
		want    [][48]byte
		wantErr bool
	}{
		{
			name: "fetch all public keys",
			args: args{
				log: entry,
				opts: &keymanager.Config{
					Location:    "Location",
					AccessToken: DefaultAccessToken,
					PubKey:      DefaultAccountPublicKey,
					Network:     "Network",
				},
			},
			want: [][48]byte{bytex.ToBytes48(pubKey)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km, err := keymanager.NewKeyManager(tt.args.log, tt.args.opts)
			require.NoError(t, err)

			got, err := km.FetchAllValidatingPublicKeys(context.Background())
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestUnknownAccount(t *testing.T) {
	km, err := keymanager.NewKeyManager(logrus.NewEntry(logrus.New()), &keymanager.Config{
		Location:    "location",
		AccessToken: "access token",
		PubKey:      "a3862121db5914d7272b0b705e6e3c5336b79e316735661873566245207329c30f9a33d4fb5f5857fc6fd0a368186972",
		Network:     "prater",
	})
	require.NoError(t, err)

	undefinedPk := _byteArray("a3862121db5914d7272b0b705e6e3c5336b79e316735661873566245207329c30f9a33d4fb5f5857fc6fd0a368186971")

	_, err = km.Sign(context.Background(), &models.SignRequest{
		PublicKey: undefinedPk,
	})
	require.EqualError(t, err, "{\"error\":\"no such key\"}")
}

func newTestRemoteWallet(handler http.HandlerFunc) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handler(writer, request)
	}))

	return s
}

func _byteArray(input string) []byte {
	res, _ := hex.DecodeString(input)
	return res
}

func _byteArray32(input string) [32]byte {
	res, _ := hex.DecodeString(input)
	var res32 [32]byte
	copy(res32[:], res)
	return res32
}
