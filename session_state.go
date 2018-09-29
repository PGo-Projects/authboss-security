package security

import "github.com/gorilla/sessions"

type SessionState struct {
	session *sessions.Session
}

func (s SessionState) Get(key string) (string, bool) {
	str, ok := s.session.Values[key]
	if !ok {
		return "", false
	}
	value := str.(string)

	return value, ok
}
