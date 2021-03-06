package backend

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/logical"
)

var (
	testCtx     = context.Background()
	testStorage = &logical.InmemStorage{}
	testBackend = func() *backend {
		conf := &logical.BackendConfig{
			System: &logical.StaticSystemView{
				DefaultLeaseTTLVal: 100 * time.Second,
				MaxLeaseTTLVal:     200 * time.Second,
			},
		}
		b := Backend(conf)
		b.Setup(context.Background(), conf)
		return b
	}()
)

func TestBackend(t *testing.T) {

	// Exercise all role endpoints.
	t.Run("write role", WriteRole)
	t.Run("read role", ReadRole)
	t.Run("list roles", ListRoles)
	t.Run("delete role", DeleteRole)

	// Plant a role for further testing.
	t.Run("plant role", WriteRole)

	// Plant a role for further testing.
	t.Run("sign with role", Sign)

	t.Run("expire keys", ExpireKeys)

}

func WriteRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/foo",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"defaults":  `{"foo":"bar"}`,
			"overrides": `{"bar":"baz"}`,
			"schema":    `{"required":["foo", "bar"]}`,
		},
	}
	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected no response because Vault generally doesn't return it for posts")
	}
}

func ReadRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/foo",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}

	// Did we get the response data we expect?
	if len(resp.Data) != 5 {
		t.Fatalf("expected 5 items in %s but received %d", resp.Data, len(resp.Data))
	}
	if resp.Data["name"] != "foo" {
		t.Fatalf("expected \"foo\" but received %q", resp.Data["name"])
	}
	if resp.Data["defaults"] != `{"foo":"bar"}` {
		t.Fatalf("expected %q but received %q", `{"foo":"bar"}`, resp.Data["defaults"])
	}
	if resp.Data["overrides"] != `{"bar":"baz"}` {
		t.Fatalf("expected %q but received %q", `{"bar":"baz"}`, resp.Data["overrides"])
	}
	if resp.Data["schema"] != `{"required":["foo", "bar"]}` {
		t.Fatalf("expected %q but received %q", `{"required":["foo", "bar"]}`, resp.Data["schema"])
	}
	if resp.Data["ttl"] != 3600 {
		t.Fatalf("expected %q but received %d", `{"required":["foo", "bar"]}`, resp.Data["ttl"])
	}
}

func ListRoles(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role/",
		Storage:   testStorage,
	}

	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	roleList := fmt.Sprintf("%s", resp.Data["keys"])
	if roleList != "[foo]" {
		t.Fatalf("expected a list of role names like \"[foo]\" but received %q", roleList)
	}
}

func DeleteRole(t *testing.T) {
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/foo",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatal("expected a nil resp, to provide a 204 with no body as the outer response")
	}
	entry, err := testStorage.Get(testCtx, "role/foo")
	if err != nil {
		t.Fatal(err)
	}
	if entry != nil {
		t.Fatal("role should no longer be stored")
	}
}

func Sign(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "sign/foo",
		Storage:   testStorage,
		Data:      map[string]interface{}{
			// "claims": `{"foo":"baz"}`,
		},
	}
	resp, err := testBackend.HandleRequest(testCtx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}

	if len(resp.Data) != 2 {
		t.Fatalf("expected 2 items in %s but received %d", resp.Data, len(resp.Data))
	}
	if resp.Data["token"] == nil {
		t.Fatalf("expected \"token\" but received %q", resp.Data["token"])
	}
	if resp.Data["expires"] == nil {
		t.Fatalf("expected \"expires\" but received %d", resp.Data["expires"])
	}

	token, err := jwt.Parse(resp.Data["token"].(string), func(t *jwt.Token) (interface{}, error) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "key/" + t.Header["kid"].(string),
			Storage:   testStorage,
		}
		resp, err := testBackend.HandleRequest(testCtx, req)
		if err != nil || (resp != nil && resp.IsError()) {
			return nil, err
		}

		block, _ := pem.Decode([]byte(resp.Data["public"].(string)))

		return x509.ParsePKCS1PublicKey(block.Bytes)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !token.Valid {
		t.Error("should be valid")
	}
}

func ExpireKeys(t *testing.T) {
	storage := &logical.InmemStorage{}
	backend := &backend{}
	ctx := context.Background()
	req := &logical.Request{Storage: storage}

	genUUID := func() string {
		t.Helper()
		id, err := uuid.GenerateUUID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	genKey := func() *rsa.PublicKey {
		t.Helper()
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return &rsaKey.PublicKey
	}

	now := time.Date(2012, 5, 1, 0, 0, 0, 0, time.UTC)

	err := writePublicKey(ctx, req, genUUID(), genKey(), now.AddDate(0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}

	err = writePublicKey(ctx, req, genUUID(), genKey(), now.AddDate(0, 0, -1))
	if err != nil {
		t.Fatal(err)
	}

	err = writePublicKey(ctx, req, genUUID(), genKey(), now.AddDate(0, 0, -2))
	if err != nil {
		t.Fatal(err)
	}

	keys, err := storage.List(ctx, "key/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Error("expected three keys")
	}

	err = backend.cleanExpiredPublicKeys(ctx, req, now)
	if err != nil {
		t.Fatal(err)
	}

	keys, err = storage.List(ctx, "key/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key but got %d", len(keys))
	}
}
