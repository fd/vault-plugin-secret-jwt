set -e

export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN="root"
unset VAULT_CACERT

sleep 2

SHASUM=$(sha256sum "/plugins/vault-plugin-secret-jwt" | cut -d " " -f1)
vault plugin register \
  -sha256=$SHASUM \
  -command=vault-plugin-secret-jwt \
  secret jwt
vault secrets enable jwt

# test write config
set -x

# Write the IAM SA
vault write jwt/role/foo 'defaults={"foo":"bar", "baz":true}'
vault read  jwt/role/foo
vault write -f jwt/sign/foo
vault write jwt/sign/foo 'claims={"foo":"bar", "baz":true}'
