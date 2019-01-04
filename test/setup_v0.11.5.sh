set -e

vault plugin register \
  -sha256=$PLUGIN_SHASUM \
  -command=vault-plugin-secret-jwt \
  jwt

vault secrets enable -plugin-name=jwt -path=jwt plugin
