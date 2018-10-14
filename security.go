package security

import (
	"net/http"

	"github.com/PGo-Projects/authboss-security/oauth2"
	"github.com/PGo-Projects/tplmgr"
	"github.com/go-chi/chi"
	"github.com/volatiletech/authboss"
	_ "github.com/volatiletech/authboss/auth"
	"github.com/volatiletech/authboss/defaults"
	"github.com/volatiletech/authboss/expire"
	_ "github.com/volatiletech/authboss/logout"
	_ "github.com/volatiletech/authboss/register"
	"github.com/volatiletech/authboss/remember"
)

type Rules = defaults.Rules

var (
	AuthBoss = authboss.New()

	db           *CredentialsStorage
	abconfig     *authBossConfig
	sessionStore SessionStorer
	cookieStore  CookieStorer
)

type ProtectedRoute struct {
	Type    string
	Path    string
	Handler http.HandlerFunc
}

func MustSetupAuthboss(config *authBossConfig, sessionName string, sessionKey []byte, cookieKey []byte) {
	sessionStore := NewSessionStorer(sessionName, sessionKey, nil)
	cookieStore := NewCookieStorer(cookieKey, nil)
	MustSetupAuthbossWithStores(config, sessionName, sessionStore, cookieStore)
}

func MustSetupAuthbossWithStores(config *authBossConfig, sessionName string, s SessionStorer, c CookieStorer) {
	db = NewCredentialsStorage(config.dbName)
	abconfig = config
	sessionStore = s
	cookieStore = c

	AuthBoss.Config.Paths.RootURL = config.rootURL
	AuthBoss.Config.Paths.NotAuthorized = config.notAuthorized
	AuthBoss.Config.Paths.AuthLoginOK = config.authLoginOK
	AuthBoss.Config.Paths.LogoutOK = config.logoutOK
	AuthBoss.Config.Paths.OAuth2LoginOK = config.oauth2LoginOK
	AuthBoss.Config.Paths.OAuth2LoginNotOK = config.oauth2LoginNotOK
	AuthBoss.Config.Paths.RegisterOK = config.registerOK
	AuthBoss.Config.Modules.LogoutMethod = "GET"
	AuthBoss.Config.Modules.ExpireAfter = config.expireAfter

	AuthBoss.Config.Storage.Server = db
	AuthBoss.Config.Storage.CookieState = cookieStore
	AuthBoss.Config.Storage.SessionState = sessionStore

	AuthBoss.Config.Core.ViewRenderer = tplmgr.NewAuthbossHTMLRendererWithExt(".tmpl")

	AuthBoss.Config.Modules.RegisterPreserveFields = []string{"username"}
	AuthBoss.Config.Modules.RoutesRedirectOnUnauthed = true

	defaults.SetCore(&AuthBoss.Config, false, false)
	AuthBoss.Config.Core.BodyReader = config.httpBodyReader

	oauth2.RegisterOAuth2Providers(AuthBoss, oauth2.GoogleProvider)

	if err := AuthBoss.Init(); err != nil {
		panic(err)
	}
}

func RegisterAuthRoutes(mux chi.Router, mountPoint string) {
	mux.Use(nosurfMiddleware, AuthBoss.LoadClientStateMiddleware)
	if abconfig.useExpire {
		mux.Use(expire.Middleware(AuthBoss), dataInjectionMiddleware)
	} else {
		mux.Use(remember.Middleware(AuthBoss), dataInjectionMiddleware)
	}
	mux.Group(func(mux chi.Router) {
		mux.Use(authboss.ModuleListMiddleware(AuthBoss))
		mux.Mount(mountPoint, http.StripPrefix(mountPoint, AuthBoss.Config.Core.Router))
	})
}

func RegisterProtectedRoutes(mux chi.Router, config ProtectedRoutesConfig, routes []ProtectedRoute) {
	mux.Group(func(mux chi.Router) {
		mux.Use(authboss.Middleware(AuthBoss, config.RedirectToLoginPage, config.ForceFullAuth, config.Force2FA))
		for _, route := range routes {
			mux.MethodFunc(route.Type, route.Path, route.Handler)
		}
	})
}
