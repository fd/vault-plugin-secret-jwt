package main

import (
	"os"

	"github.com/fd/vault-plugin-secret-jwt/backend"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/logical/plugin"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	var (
		tlsConfig       = apiClientMeta.GetTLSConfig()
		tlsProviderFunc = pluginutil.VaultPluginTLSProvider(tlsConfig)
	)

	logger := hclog.New(&hclog.LoggerOptions{})

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
		TLSProviderFunc:    tlsProviderFunc,
		Logger:             logger,
	})
	if err != nil {
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
