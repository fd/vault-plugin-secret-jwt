set -e

sh /test/configure.sh &
# exec vault server -log-level=trace -dev -dev-root-token-id="root" -config=/test/vault.hcl
exec vault server -dev -dev-root-token-id="root" -config=/test/vault.hcl
