package backend

import (
	"context"
	"errors"
	"fmt"
	"path"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func rolePaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern:      "role/?",
			HelpSynopsis: ``,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList,
			},
		},
		&framework.Path{
			Pattern:      "role/" + framework.GenericNameRegex("name"),
			HelpSynopsis: ``,
			Fields: map[string]*framework.FieldSchema{
				"name":      &framework.FieldSchema{Type: framework.TypeNameString},
				"defaults":  &framework.FieldSchema{Type: framework.TypeString},
				"overrides": &framework.FieldSchema{Type: framework.TypeString},
				"schema":    &framework.FieldSchema{Type: framework.TypeString},
				"ttl":       &framework.FieldSchema{Type: framework.TypeDurationSecond, Default: 3600},
			},
			ExistenceCheck: b.pathRoleExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathRoleRead,
				logical.CreateOperation: b.pathRoleCreateUpdate,
				logical.UpdateOperation: b.pathRoleCreateUpdate,
				logical.DeleteOperation: b.pathRoleDelete,
			},
		},
		&framework.Path{
			Pattern:      "sign/" + framework.GenericNameRegex("rolename"),
			HelpSynopsis: ``,
			Fields: map[string]*framework.FieldSchema{
				"rolename": &framework.FieldSchema{Type: framework.TypeNameString},
				"claims":   &framework.FieldSchema{Type: framework.TypeString},
			},
			ExistenceCheck: b.pathRoleExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathRoleSign,
				logical.UpdateOperation: b.pathRoleSign,
			},
		},
	}
}

// EntityID

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}

func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %v", err)
	}

	return out != nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.getRole(ctx, req, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":      data.Get("name").(string),
			"defaults":  string(role.Defaults),
			"overrides": string(role.Overrides),
			"schema":    string(role.Schema),
			"ttl":       role.TTL,
		},
	}, nil
}

func (b *backend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.getRole(ctx, req, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &Role{}
	}

	role.Defaults = []byte(data.Get("defaults").(string))
	role.Overrides = []byte(data.Get("overrides").(string))
	role.Schema = []byte(data.Get("schema").(string))
	role.TTL = data.Get("ttl").(int)
	if role.TTL <= 0 {
		role.TTL = 3600 // 1h
	}
	if role.TTL > 86400 {
		role.TTL = 86400 // 24h
	}

	err = role.Validate()
	if err != nil {
		return errorResponse(err) // CodedError(400, err)
	}

	entry, err := logical.StorageEntryJSON(req.Path, role)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, req.Path)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) getRole(ctx context.Context, req *logical.Request, roleName string) (*Role, error) {
	entry, err := req.Storage.Get(ctx, path.Join("role", roleName))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role *Role

	err = entry.DecodeJSON(&role)
	if err != nil {
		return nil, fmt.Errorf("unmarshal failed: %v", err)
	}

	return role, nil
}

func (b *backend) pathRoleSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.getRole(ctx, req, data.Get("rolename").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, errors.New("no such role")
	}

	claims := []byte(data.Get("claims").(string))

	jwtClaims, expires, err := role.BuildClaims(claims, req.ID)
	if err != nil {
		return nil, err
	}

	key, err := b.currentKey.Get(ctx, req)
	if err != nil {
		return nil, err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)
	token.Header["kid"] = key.ID
	jwtToken, err := token.SignedString(key.prvKey)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"token":   jwtToken,
			"expires": expires.Unix(),
		},
	}, nil
}
