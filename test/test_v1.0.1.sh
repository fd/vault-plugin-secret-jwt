set -e
set -x

SHASUM=$(sha256sum "$(go env GOPATH)/bin/vault-plugin-secret-jwt" | cut -d " " -f1)
vault plugin register \
  -sha256=$SHASUM \
  -command=vault-plugin-secret-jwt \
  secret jwt

vault secrets enable jwt

vault write jwt/role/foo 'defaults={"foo":"bar", "baz":true}'
vault read  jwt/role/foo
vault write -f jwt/sign/foo
