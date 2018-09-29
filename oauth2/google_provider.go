package oauth2

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
	aboauth "github.com/volatiletech/authboss/oauth2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	GoogleProvider     = "google"
	googleInfoEndpoint = `https://www.googleapis.com/userinfo/v2/me`
)

func getGoogleProviderConfig() (authboss.OAuth2Provider, error) {
	oauthcreds := struct {
		ClientID     string `toml:"client_id"`
		ClientSecret string `toml:"client_secret"`
	}{}

	_, err := toml.DecodeFile("google_oauth2.toml", &oauthcreds)
	if err == nil && len(oauthcreds.ClientID) != 0 && len(oauthcreds.ClientSecret) != 0 {
		provider := authboss.OAuth2Provider{
			OAuth2Config: &oauth2.Config{
				ClientID:     oauthcreds.ClientID,
				ClientSecret: oauthcreds.ClientSecret,
				Scopes:       []string{`profile`, `email`},
				Endpoint:     google.Endpoint,
			},
			FindUserDetails: GoogleUserDetails,
		}
		return provider, nil
	}
	return authboss.OAuth2Provider{}, err
}

type googleResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func GoogleUserDetails(ctx context.Context, cfg oauth2.Config, token *oauth2.Token) (map[string]string, error) {
	client := cfg.Client(ctx, token)
	resp, err := (*http.Client).Get(client, googleInfoEndpoint)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	byt, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read body from google oauth2 endpoint")
	}

	var response googleResponse
	if err = json.Unmarshal(byt, &response); err != nil {
		return nil, err
	}

	return map[string]string{
		aboauth.OAuth2UID:   response.ID,
		aboauth.OAuth2Email: response.Email,
		aboauth.OAuth2Name:  response.Name,
	}, nil
}
