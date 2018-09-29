package security

import "time"

type ProtectedRoutesConfig struct {
	RedirectToLoginPage bool
	ForceFullAuth       bool
	Force2FA            bool
}

type authBossConfig struct {
	dbName      string
	rootURL     string
	useExpire   bool
	expireAfter time.Duration

	httpBodyReader HTTPBodyReader
}

type authBossConfigBuilder struct {
	dbName      string
	rootURL     string
	useExpire   bool
	expireAfter time.Duration

	httpBodyReader HTTPBodyReader
}

func NewAuthBossConfigBuilder(dbName string, httpBodyReader HTTPBodyReader) *authBossConfigBuilder {
	return &authBossConfigBuilder{
		dbName:         dbName,
		rootURL:        "http://localhost:8080",
		useExpire:      false,
		expireAfter:    0 * time.Second,
		httpBodyReader: httpBodyReader,
	}
}

func (b *authBossConfigBuilder) WithRootURL(rootURL string) *authBossConfigBuilder {
	b.rootURL = rootURL
	return b
}

func (b *authBossConfigBuilder) WithExpireAfter(expireAfter time.Duration) *authBossConfigBuilder {
	b.useExpire = true
	b.expireAfter = expireAfter
	return b
}

func (b *authBossConfigBuilder) Build() *authBossConfig {
	return &authBossConfig{
		dbName:         b.dbName,
		rootURL:        b.rootURL,
		useExpire:      b.useExpire,
		expireAfter:    b.expireAfter,
		httpBodyReader: b.httpBodyReader,
	}
}
