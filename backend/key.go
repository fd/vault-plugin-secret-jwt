package backend

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"path"
	"sync"
	"time"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/logical"
)

type currentKey struct {
	mtx    sync.RWMutex
	prvKey *PrivateKey
}

type PrivateKey struct {
	ID      string
	Expires time.Time
	DER     []byte

	mtx    sync.RWMutex
	prvKey *rsa.PrivateKey
}

func (c *currentKey) Get(ctx context.Context, req *logical.Request) (*PrivateKey, error) {
	c.mtx.RLock()
	key := c.prvKey
	c.mtx.RUnlock()

	if key != nil && key.Expires.After(time.Now()) {
		return decodePrivateKey(key, nil)
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	key = c.prvKey
	if key != nil && key.Expires.After(time.Now()) {
		return decodePrivateKey(key, nil)
	}

	entry, err := req.Storage.Get(ctx, "privatekey")
	if err != nil {
		return nil, err
	}
	if entry != nil {
		err = entry.DecodeJSON(&key)
		if err != nil {
			return nil, err
		}

		if key != nil && key.Expires.After(time.Now()) {
			c.prvKey = key
			return decodePrivateKey(key, nil)
		}
	}

	keyID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	pubDer, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, err
	}

	prvDer, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		return nil, err
	}

	key = &PrivateKey{
		ID:      keyID,
		Expires: time.Now().AddDate(0, 0, 1).UTC(),
		DER:     prvDer,

		prvKey: rsaKey,
	}

	entry, err = logical.StorageEntryJSON("privatekey", key)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	entry, err = logical.StorageEntryJSON(path.Join("key", keyID), &Key{
		PublicPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubDer,
		}),
	})
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	c.prvKey = key
	return decodePrivateKey(key, nil)
}

func decodePrivateKey(k *PrivateKey, e error) (*PrivateKey, error) {
	if e != nil {
		return nil, e
	}
	if k == nil {
		return nil, nil
	}

	e = k.decodePrivateKey()
	if e != nil {
		return nil, e
	}

	return k, nil
}

func (k *PrivateKey) decodePrivateKey() error {
	k.mtx.RLock()
	prvKey := k.prvKey
	k.mtx.RUnlock()

	if prvKey != nil {
		return nil
	}

	k.mtx.Lock()
	defer k.mtx.Unlock()

	prvKey = k.prvKey
	if prvKey != nil {
		return nil
	}

	prvKeyI, err := x509.ParsePKCS8PrivateKey(k.DER)
	if err != nil {
		return err
	}

	prvKey, _ = prvKeyI.(*rsa.PrivateKey)
	if prvKey == nil {
		return errors.New("invalid private key")
	}

	k.prvKey = prvKey
	return nil
}
