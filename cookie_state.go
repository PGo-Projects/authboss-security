package security

type CookieState map[string]string

func (cs CookieState) Get(key string) (string, bool) {
	cookie, ok := cs[key]
	return cookie, ok
}
