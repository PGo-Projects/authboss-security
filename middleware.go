package security

import (
	"context"
	"log"
	"net/http"

	"github.com/justinas/nosurf"
	"github.com/volatiletech/authboss"
)

func nosurfMiddleware(h http.Handler) http.Handler {
	nosurfHandler := nosurf.New(h)
	nosurfHandler.SetFailureHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Failed to validate CSRF token:", nosurf.Reason(r))
		w.WriteHeader(http.StatusBadRequest)
	}))
	return nosurfHandler
}

func dataInjectionMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := securityData(w, &r)
		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyData, data))
		h.ServeHTTP(w, r)
	})
}

func securityData(w http.ResponseWriter, r **http.Request) authboss.HTMLData {
	currentUserName := ""
	if currentUser, err := AuthBoss.LoadCurrentUser(r); err == nil && currentUser != nil {
		currentUserName = currentUser.(*User).Name
	}

	return authboss.HTMLData{
		"loggedin":          currentUserName != "",
		"current_user_name": currentUserName,
		"csrf_token":        nosurf.Token(*r),
		"flash_success":     authboss.FlashSuccess(w, *r),
		"flash_error":       authboss.FlashError(w, *r),
	}
}
