package security

import (
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/volatiletech/authboss"
)

type SessionStorer interface {
	authboss.ClientStateReadWriter
}

type sessionStorer struct {
	name  string
	store sessions.Store
}

type sessionStorerBuilder struct {
	name     string
	keypairs [][]byte

	path     string
	maxAge   int
	secure   bool
	httpOnly bool
}

func NewSessionStorer(sessionName string, keypairs ...[]byte) SessionStorer {
	return sessionStorer{
		name:  sessionName,
		store: sessions.NewCookieStore(keypairs...),
	}
}

func NewSessionStorerBuilder(sessionName string, keypairs ...[]byte) *sessionStorerBuilder {
	return &sessionStorerBuilder{
		name:     sessionName,
		keypairs: keypairs,

		path:     "/",
		maxAge:   86400 * 30,
		secure:   false,
		httpOnly: false,
	}
}

func (b *sessionStorerBuilder) WithPath(path string) *sessionStorerBuilder {
	b.path = path
	return b
}

func (b *sessionStorerBuilder) WithMaxAge(maxAge int) *sessionStorerBuilder {
	b.maxAge = maxAge
	return b
}

func (b *sessionStorerBuilder) WithSecure(secure bool) *sessionStorerBuilder {
	b.secure = secure
	return b
}

func (b *sessionStorerBuilder) WithHttpOnly(httpOnly bool) *sessionStorerBuilder {
	b.httpOnly = httpOnly
	return b
}

func (b *sessionStorerBuilder) Build() SessionStorer {
	cs := &sessions.CookieStore{
		Codecs: securecookie.CodecsFromPairs(b.keypairs...),
		Options: &sessions.Options{
			Path:     b.path,
			MaxAge:   b.maxAge,
			Secure:   b.secure,
			HttpOnly: b.httpOnly,
		},
	}
	cs.MaxAge(b.maxAge)

	return sessionStorer{
		name:  b.name,
		store: cs,
	}
}

func (s sessionStorer) ReadState(r *http.Request) (authboss.ClientState, error) {
	session, err := s.store.Get(r, s.name)
	if err != nil {
		e, ok := err.(securecookie.Error)
		if ok && !e.IsDecode() {
			return nil, err
		}

		session, err = s.store.New(r, s.name)
		if err != nil {
			return nil, err
		}
	}

	cs := &SessionState{
		session: session,
	}
	return cs, nil
}

func (s sessionStorer) WriteState(w http.ResponseWriter, state authboss.ClientState, events []authboss.ClientStateEvent) error {
	session := state.(*SessionState)

	for _, ev := range events {
		switch ev.Kind {
		case authboss.ClientStateEventPut:
			session.session.Values[ev.Key] = ev.Value
		case authboss.ClientStateEventDel:
			delete(session.session.Values, ev.Key)
		}
	}

	return s.store.Save(nil, w, session.session)
}
