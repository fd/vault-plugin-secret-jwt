package backend

import (
	"context"
	"fmt"
	"path"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type Key struct {
	Expires   time.Time
	PublicPEM []byte
}

func keyPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern:      "key/" + framework.GenericNameRegex("name"),
			HelpSynopsis: ``,
			Fields: map[string]*framework.FieldSchema{
				"name":   &framework.FieldSchema{Type: framework.TypeNameString},
				"public": &framework.FieldSchema{Type: framework.TypeString},
			},
			ExistenceCheck: b.pathKeyExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathKeyRead,
			},
		},
	}
}

func (b *backend) pathKeyExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %v", err)
	}

	return out != nil, nil
}

func (b *backend) pathKeyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	key, err := b.getKey(ctx, req, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":   data.Get("name").(string),
			"public": string(key.PublicPEM),
		},
	}, nil
}

func (b *backend) getKey(ctx context.Context, req *logical.Request, keyName string) (*Key, error) {
	entry, err := req.Storage.Get(ctx, path.Join("key", keyName))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var key *Key

	err = entry.DecodeJSON(&key)
	if err != nil {
		return nil, fmt.Errorf("unmarshal failed: %v", err)
	}

	return key, nil
}

func (b *backend) cleanExpiredPublicKeys(ctx context.Context, req *logical.Request, now time.Time) error {
	keys, err := req.Storage.List(ctx, "key/")
	if err != nil {
		return err
	}

	for _, keyID := range keys {
		err := b.cleanExpiredPublicKey(ctx, req, now, keyID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *backend) cleanExpiredPublicKey(ctx context.Context, req *logical.Request, now time.Time, keyID string) error {
	key, err := b.getKey(ctx, req, keyID)
	if err != nil {
		return err
	}

	expires := key.Expires
	if !expires.IsZero() && now.Before(expires) {
		return nil
	}

	err = req.Storage.Delete(ctx, path.Join("key", keyID))
	if err != nil {
		return err
	}

	return nil
}
