package oauth2

import (
	"log"
	"os"

	"github.com/volatiletech/authboss"
)

func RegisterOAuth2Providers(authBoss *authboss.Authboss, providers ...string) {
	log.Println("Configuring OAuth2 providers...")
	configuredProviders := make(map[string]authboss.OAuth2Provider)

	var config authboss.OAuth2Provider
	var err error
	for _, provider := range providers {
		switch provider {
		case GoogleProvider:
			config, err = getGoogleProviderConfig()
		}

		if err == nil {
			configuredProviders[provider] = config
		} else if !os.IsNotExist(err) {
			log.Printf("Error configuring %s OAuth2", err)
		}
	}

	authBoss.Config.Modules.OAuth2Providers = configuredProviders
}
