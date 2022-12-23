// Package feishu implements the OAuth2 protocol for authenticating users through feishu.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package feishu

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// These vars define the default Authentication, Token, and Profile URLS for Feishu.
//
// Examples:
//
//	feishu.AuthURL = "https://passport.feishu.cn/suite/passport/oauth/authorize"
//	feishu.TokenURL = "https://passport.feishu.cn/suite/passport/oauth/token"
//	feishu.ProfileURL = "https://passport.feishu.cn/suite/passport/oauth/userinfo"
var (
	AuthURL    = "https://passport.feishu.cn/suite/passport/oauth/authorize"
	TokenURL   = "https://passport.feishu.cn/suite/passport/oauth/token"
	ProfileURL = "https://passport.feishu.cn/suite/passport/oauth/userinfo"
)

// Provider is the implementation of `goth.Provider` for accessing Feishu.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	authURL      string
	tokenURL     string
	profileURL   string
}

// New creates a new Feishu provider and sets up important connection details.
// You should always call `feishu.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	return NewCustomisedURL(clientKey, secret, callbackURL, AuthURL, TokenURL, ProfileURL, scopes...)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL, profileURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "feishu",
		profileURL:   profileURL,
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the feishu package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Feishu for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Feishu and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", p.profileURL, nil)
	if err != nil {
		return user, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", sess.AccessToken))

	response, err := p.Client().Do(req)
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return user, err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)

	return user, err
}

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	}
	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Name      string `json:"name"`
		Email     string `json:"email"`
		ID        string `json:"user_id"`
		AvatarURL string `json:"avatar_url"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	user.Email = u.Email
	user.Name = u.Name
	user.NickName = u.Name
	user.UserID = u.ID
	user.AvatarURL = u.AvatarURL
	return nil
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	req, err := http.NewRequest(http.MethodPost, TokenURL, nil)
	if err != nil {
		return nil, err
	}

	// Set up the url params to post to get a new access token from a code
	v := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	req.URL.RawQuery = v.Encode()
	refreshResponse, err := p.Client().Do(req)
	if err != nil {
		return nil, err
	}

	// We get the body bytes in case we need to parse an error response
	bodyBytes, err := ioutil.ReadAll(refreshResponse.Body)
	if err != nil {
		return nil, err
	}
	defer refreshResponse.Body.Close()

	refresh := struct {
		AccessToken      string `json:"access_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int64  `json:"expires_in"`
		RefreshToken     string `json:"refresh_token"`
		RefreshExpiresIn int64  `json:"refresh_expires_in"`
	}{}
	err = json.Unmarshal(bodyBytes, &refresh)
	if err != nil {
		return nil, err
	}

	token := &oauth2.Token{
		AccessToken:  refresh.AccessToken,
		TokenType:    refresh.TokenType,
		RefreshToken: refresh.RefreshToken,
		Expiry:       time.Now().Add(time.Second * time.Duration(refresh.ExpiresIn)),
	}

	tokenExtra := map[string]interface{}{
		"refresh_expires_in": refresh.RefreshExpiresIn,
	}

	return token.WithExtra(tokenExtra), nil
}
