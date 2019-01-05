set -e

vault plugin register \
  -sha256=$PLUGIN_SHASUM \
  -command=vault-plugin-secret-jwt \
  secret jwt

vault secrets enable jwt
