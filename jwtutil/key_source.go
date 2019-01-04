package jwtutil

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"sync"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
)

type KeySource struct {
	mountPath string
	client    *api.Client

	mtx   sync.RWMutex
	cache map[string]interface{}
}

func NewKeySource(vaultClient *api.Client, mountPath string) *KeySource {
	return &KeySource{
		mountPath: mountPath,
		client:    vaultClient,
		cache:     make(map[string]interface{}, 64),
	}
}

func (ks *KeySource) LookupKey(keyID string) (interface{}, error) {
	// validate key id
	uuid, err := uuid.ParseUUID(keyID)
	if err != nil || len(uuid) == 0 {
		return nil, err
	}

	// lookup in cache with read lock
	ks.mtx.RLock()
	key := ks.cache[keyID]
	ks.mtx.RUnlock()
	if key != nil {
		return key, nil
	}

	ks.mtx.Lock()
	defer ks.mtx.Unlock()

	// lookup in cache with write lock
	key = ks.cache[keyID]
	if key != nil {
		return key, nil
	}

	// lookup in vault
	key, err = ks.lookupKey(keyID)
	if err != nil {
		return nil, err
	}

	// store in cache
	ks.cache[keyID] = key
	return key, nil
}

func (ks *KeySource) lookupKey(keyID string) (interface{}, error) {
	sec, err := ks.client.Logical().Read(ks.mountPath + "/key/" + keyID)
	if err != nil {
		return nil, err
	}
	if sec == nil {
		return nil, errors.New("signing key not found")
	}

	pemString, _ := sec.Data["public"].(string)
	if pemString == "" {
		return nil, errors.New("signing key not found")
	}

	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, errors.New("signing key not found")
	}

	if block.Type == "PUBLIC KEY" || strings.HasSuffix(block.Type, " PUBLIC KEY") {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	return nil, errors.New("invalid signing key")
}
