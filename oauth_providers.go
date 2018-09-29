package security

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
	aboauth "github.com/volatiletech/authboss/oauth2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	GoogleProvider = "google"
)

func RegisterOAuth(providers ...string) {
	log.Println("Configuring OAuth2...")
	configuredProviders := make(map[string]authboss.OAuth2Provider)

	for _, provider := range providers {
		switch provider {
		case GoogleProvider:
			oauthcreds := struct {
				ClientID     string `toml:"client_id"`
				ClientSecret string `toml:"client_secret"`
			}{}

			_, err := toml.DecodeFile("google_oauth2.toml", &oauthcreds)
			if err == nil && len(oauthcreds.ClientID) != 0 && len(oauthcreds.ClientSecret) != 0 {
				configuredProviders["google"] = authboss.OAuth2Provider{
					OAuth2Config: &oauth2.Config{
						ClientID:     oauthcreds.ClientID,
						ClientSecret: oauthcreds.ClientSecret,
						Scopes:       []string{`profile`, `email`},
						Endpoint:     google.Endpoint,
					},
					FindUserDetails: GoogleUserDetails,
				}
			} else if !os.IsNotExist(err) {
				log.Println("Error configuring Google OAuth2:", err)
			}
		}
	}
	AuthBoss.Config.Modules.OAuth2Providers = configuredProviders
}

type googleMeResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func GoogleUserDetails(ctx context.Context, cfg oauth2.Config, token *oauth2.Token) (map[string]string, error) {
	client := cfg.Client(ctx, token)
	googleInfoEndpoint := `https://www.googleapis.com/userinfo/v2/me`
	resp, err := (*http.Client).Get(client, googleInfoEndpoint)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	byt, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read body from google oauth2 endpoint")
	}

	var response googleMeResponse
	if err = json.Unmarshal(byt, &response); err != nil {
		return nil, err
	}

	return map[string]string{
		aboauth.OAuth2UID:   response.ID,
		aboauth.OAuth2Email: response.Email,
		aboauth.OAuth2Name:  response.Name,
	}, nil
}
