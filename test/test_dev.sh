set -e

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." >/dev/null 2>&1 && pwd )"
DIR="${ROOT}/test"
version="$1"

# Build plugin
cd "$ROOT"
mkdir -p "$DIR/plugins"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$DIR/plugins/vault-plugin-secret-jwt" -v .
export PLUGIN_SHASUM=$(shasum -a 256 "$DIR/plugins/vault-plugin-secret-jwt" | cut -d " " -f1)

# Fetch vault client
platform="$(go env GOOS)_$(go env GOARCH)"
if [ ! -e "$DIR/vault_${version}/vault" ]; then
  mkdir -p "$DIR/vault_${version}"
  curl https://releases.hashicorp.com/vault/${version}/vault_${version}_${platform}.zip > "$DIR/vault_${version}.zip"
  unzip -o -d "$DIR/vault_${version}" "$DIR/vault_${version}.zip"
fi
export PATH="$DIR/vault_${version}:$PATH"

# Start vault
docker_args=(
  -d
  --rm
  -p 8200:8200
  -v "$DIR/plugins:/plugins"
  -v "$DIR/vault.hcl:/etc/vault.hcl"
)

vault_args=(
  server
  -dev
  -dev-root-token-id="root"
  -config=/etc/vault.hcl
)

container_id="$(docker run ${docker_args[*]} "vault:${version}" ${vault_args[*]})"
function finish {
  docker stop "$container_id" > /dev/null
}
trap finish EXIT
sleep 2

# Setup env
export VAULT_TOKEN=root VAULT_ADDR=http://localhost:8200
unset VAULT_CA

cd "$DIR"
bash ./setup_v${version}.sh

cd "$ROOT"
./node_modules/mocha/bin/mocha
