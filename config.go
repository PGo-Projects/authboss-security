package security

import "time"

type ProtectedRoutesConfig struct {
	RedirectToLoginPage bool
	ForceFullAuth       bool
	Force2FA            bool
}

type authBossConfig struct {
	dbName  string
	rootURL string

	notAuthorized    string
	authLoginOK      string
	logoutOK         string
	oauth2LoginOK    string
	oauth2LoginNotOK string
	registerOK       string

	useExpire   bool
	expireAfter time.Duration

	httpBodyReader HTTPBodyReader
}

type authBossConfigBuilder struct {
	dbName  string
	rootURL string

	notAuthorized    string
	authLoginOK      string
	logoutOK         string
	oauth2LoginOK    string
	oauth2LoginNotOK string
	registerOK       string

	useExpire   bool
	expireAfter time.Duration

	httpBodyReader HTTPBodyReader
}

func NewAuthBossConfigBuilder(dbName string, httpBodyReader HTTPBodyReader) *authBossConfigBuilder {
	return &authBossConfigBuilder{
		dbName:  dbName,
		rootURL: "http://localhost:8080",

		notAuthorized:    "/",
		authLoginOK:      "/",
		logoutOK:         "/",
		oauth2LoginOK:    "/",
		oauth2LoginNotOK: "/",
		registerOK:       "/",

		useExpire:      false,
		expireAfter:    0 * time.Second,
		httpBodyReader: httpBodyReader,
	}
}

func (b *authBossConfigBuilder) WithRootURL(rootURL string) *authBossConfigBuilder {
	b.rootURL = rootURL
	return b
}

func (b *authBossConfigBuilder) WithNotAuthorized(url string) *authBossConfigBuilder {
	b.notAuthorized = url
	return b
}

func (b *authBossConfigBuilder) WithAuthLoginOK(url string) *authBossConfigBuilder {
	b.authLoginOK = url
	return b
}

func (b *authBossConfigBuilder) WithLogoutOK(url string) *authBossConfigBuilder {
	b.logoutOK = url
	return b
}

func (b *authBossConfigBuilder) WithOAuth2LoginOK(url string) *authBossConfigBuilder {
	b.oauth2LoginOK = url
	return b
}

func (b *authBossConfigBuilder) WithOAuth2LoginNotOK(url string) *authBossConfigBuilder {
	b.oauth2LoginNotOK = url
	return b
}

func (b *authBossConfigBuilder) WithRegisterOK(url string) *authBossConfigBuilder {
	b.registerOK = url
	return b
}

func (b *authBossConfigBuilder) WithExpireAfter(expireAfter time.Duration) *authBossConfigBuilder {
	b.useExpire = true
	b.expireAfter = expireAfter
	return b
}

func (b *authBossConfigBuilder) Build() *authBossConfig {
	return &authBossConfig{
		dbName:  b.dbName,
		rootURL: b.rootURL,

		notAuthorized:    b.notAuthorized,
		authLoginOK:      b.authLoginOK,
		logoutOK:         b.logoutOK,
		oauth2LoginOK:    b.oauth2LoginOK,
		oauth2LoginNotOK: b.oauth2LoginNotOK,
		registerOK:       b.registerOK,

		useExpire:      b.useExpire,
		expireAfter:    b.expireAfter,
		httpBodyReader: b.httpBodyReader,
	}
}
