package keymanager

import (
	"encoding/json"
	"io"

	"github.com/pkg/errors"
)

// Config contains configuration of the remote HTTP keymanager
type Config struct {
	Location    string `json:"location"`
	AccessToken string `json:"access_token"`
	PubKey      string `json:"public_key"`
	Network     string `json:"network"`
}

// UnmarshalConfigFile attempts to JSON unmarshal a keymanager
// configuration file into the *Config{} struct.
func UnmarshalConfigFile(r io.ReadCloser) (*Config, error) {
	enc, err := io.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "could not read config")
	}
	defer r.Close()

	var cfg Config
	if err := json.Unmarshal(enc, &cfg); err != nil {
		return nil, errors.Wrap(err, "could not JSON unmarshal")
	}
	return &cfg, nil
}
