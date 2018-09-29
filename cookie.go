package security

import (
	"crypto/cipher"
	"hash"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
)

var (
	defaultCookieList = []string{authboss.CookieRemember}
)

type CookieStorer interface {
	authboss.ClientStateReadWriter

	WithBlockFunc(f func([]byte) (cipher.Block, error)) CookieStorer
	WithHashFunc(f func() hash.Hash) CookieStorer
	WithMinAge(minAge int) CookieStorer
	WithMaxAge(maxAge int) CookieStorer
	WithMaxLength(maxLength int) CookieStorer
	WithSecure(secure bool) CookieStorer
	WithHttpOnly(httpOnly bool) CookieStorer
}

type cookieStorer struct {
	cookies      []string
	secureCookie *securecookie.SecureCookie

	maxAge   int
	secure   bool
	httpOnly bool
}

func NewCookieStorer(hashKey, blockKey []byte) CookieStorer {
	return &cookieStorer{
		cookies:      defaultCookieList,
		secureCookie: securecookie.New(hashKey, blockKey),

		maxAge: 30 * 86400,
	}
}

func (c *cookieStorer) WithBlockFunc(f func([]byte) (cipher.Block, error)) CookieStorer {
	c.secureCookie = c.secureCookie.BlockFunc(f)
	return c
}

func (c *cookieStorer) WithHashFunc(f func() hash.Hash) CookieStorer {
	c.secureCookie = c.secureCookie.HashFunc(f)
	return c
}

func (c *cookieStorer) WithMinAge(minAge int) CookieStorer {
	c.secureCookie = c.secureCookie.MinAge(minAge)
	return c
}

func (c *cookieStorer) WithMaxAge(maxAge int) CookieStorer {
	c.secureCookie = c.secureCookie.MaxAge(maxAge)
	c.maxAge = maxAge
	return c
}

func (c *cookieStorer) WithMaxLength(maxLength int) CookieStorer {
	c.secureCookie = c.secureCookie.MaxLength(maxLength)
	return c
}

func (c *cookieStorer) WithSecure(secure bool) CookieStorer {
	c.secure = secure
	return c
}

func (c *cookieStorer) WithHttpOnly(httpOnly bool) CookieStorer {
	c.httpOnly = httpOnly
	return c
}

func (c cookieStorer) ReadState(r *http.Request) (authboss.ClientState, error) {
	cookieState := make(CookieState)

	for _, cookie := range r.Cookies() {
		for _, name := range c.cookies {
			if name == cookie.Name {
				var str string
				if err := c.secureCookie.Decode(name, cookie.Value, &str); err != nil {
					if e, ok := err.(securecookie.Error); ok {
						if e.IsDecode() {
							continue
						}
					}
					return nil, err
				}
				cookieState[name] = str
			}
		}
	}

	return cookieState, nil
}

func (c cookieStorer) WriteState(w http.ResponseWriter, state authboss.ClientState, events []authboss.ClientStateEvent) error {
	for _, ev := range events {
		switch ev.Kind {
		case authboss.ClientStateEventPut:
			encoded, err := c.secureCookie.Encode(ev.Key, ev.Value)
			if err != nil {
				return errors.Wrap(err, "failed to encode cookie")
			}

			cookie := &http.Cookie{
				Expires:  time.Now().UTC().Add(time.Duration(c.maxAge) * time.Second),
				MaxAge:   c.maxAge,
				Name:     ev.Key,
				Value:    encoded,
				Path:     "/",
				HttpOnly: c.httpOnly,
				Secure:   c.secure,
			}
			http.SetCookie(w, cookie)
		case authboss.ClientStateEventDel:
			cookie := &http.Cookie{
				Expires:  time.Now().UTC().Add(-1 * time.Hour),
				MaxAge:   -1,
				Name:     ev.Key,
				Path:     "/",
				HttpOnly: c.httpOnly,
				Secure:   c.secure,
			}
			http.SetCookie(w, cookie)
		}
	}

	return nil
}
