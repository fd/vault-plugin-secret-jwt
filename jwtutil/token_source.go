package jwtutil

import (
	"encoding/json"
	"errors"
	"path"
	"time"

	"github.com/hashicorp/vault/api"
	"golang.org/x/oauth2"
)

type TokenSourceConfig struct {
	// Mount path of the jwt secret backend. Defaults to "jwt"
	Mount string

	// Role name of the role
	Role string

	// Claims to include in the JWTs
	Claims map[string]interface{}

	// Client for accessing Vault
	Client *api.Client
}

type tokenSource struct {
	path   string
	claims string
	client *api.Client
}

var _ oauth2.TokenSource = (*tokenSource)(nil)

// NewTokenSource makes a new token source
func NewTokenSource(config TokenSourceConfig) (oauth2.TokenSource, error) {
	if config.Mount == "" {
		config.Mount = "jwt"
	}

	ts := &tokenSource{
		path:   path.Join(config.Mount, "sign", config.Role),
		client: config.Client,
	}

	if config.Claims != nil {
		claims, err := json.Marshal(config.Claims)
		if err != nil {
			return nil, err
		}
		ts.claims = string(claims)
	}

	return oauth2.ReuseTokenSource(nil, ts), nil
}

func (ts *tokenSource) Token() (*oauth2.Token, error) {
	sec, err := ts.client.Logical().Write(ts.path, map[string]interface{}{
		"claims": ts.claims,
	})
	if err != nil {
		return nil, err
	}
	if sec == nil {
		return nil, errors.New("no token")
	}

	token, _ := sec.Data["token"].(string)
	if token == "" {
		return nil, errors.New("no token")
	}

	expires, _ := sec.Data["expires"].(int)
	if expires <= 0 {
		return nil, errors.New("no token")
	}

	return &oauth2.Token{
		TokenType:   "Bearer",
		AccessToken: token,
		Expiry:      time.Unix(int64(expires-5), 0), // include 5 second grace time
	}, nil
}
