package feishu

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/markbates/goth"
)

// Session stores data during the auth process with Gitea.
type Session struct {
	AuthURL          string
	AccessToken      string
	RefreshToken     string
	ExpiresAt        time.Time
	RefreshExpiresAt time.Time
}

var _ goth.Session = &Session{}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Gitea provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with Gitea and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)

	// Set up the url params to post to get a new access token from a code
	v := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {params.Get("code")},
	}
	if p.config.RedirectURL != "" {
		v.Set("redirect_uri", p.config.RedirectURL)
	}

	req, err := http.NewRequest(http.MethodPost, TokenURL, nil)
	if err != nil {
		return "", err
	}
	v.Add("client_key", p.config.ClientID)
	v.Add("client_secret", p.config.ClientSecret)

	req.URL.RawQuery = v.Encode()
	response, err := p.Client().Do(req)
	if err != nil {
		return "", err
	}

	tokenResp := struct {
		AccessToken      string `json:"access_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int64  `json:"expires_in"`
		RefreshToken     string `json:"refresh_token"`
		RefreshExpiresIn int64  `json:"refresh_expires_in"`
	}{}

	// Get the body bytes in case we have to parse an error response
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	err = json.Unmarshal(bodyBytes, &tokenResp)
	if err != nil {
		return "", err
	}

	// Create and Bind the Access Token
	s.AccessToken = tokenResp.AccessToken
	s.ExpiresAt = time.Now().UTC().Add(time.Second * time.Duration(tokenResp.ExpiresIn))
	s.RefreshToken = tokenResp.RefreshToken
	s.RefreshExpiresAt = time.Now().UTC().Add(time.Second * time.Duration(tokenResp.RefreshExpiresIn))
	return s.AccessToken, nil
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession wil unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}
