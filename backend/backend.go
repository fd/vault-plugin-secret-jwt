package backend

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend returns a private embedded struct of framework.Backend.
func Backend(conf *logical.BackendConfig) *backend {
	var b backend

	b.Backend = &framework.Backend{
		Help: "",
		Paths: framework.PathAppend(
			keyPaths(&b),
			rolePaths(&b),
		),
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"key/"},
			SealWrapStorage: []string{"privatekey"},
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
	}

	return &b
}

type backend struct {
	*framework.Backend
	currentKey
}
