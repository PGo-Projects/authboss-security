package security

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/defaults"
)

type HTTPFormValidator = defaults.HTTPFormValidator

const (
	FormValueEmail    = "email"
	FormValuePassword = "password"
	FormValueUsername = "username"

	FormValueConfirm      = "cnf"
	FormValueToken        = "token"
	FormValueCode         = "code"
	FormValueRecoveryCode = "recovery_code"
	FormValuePhoneNumber  = "phone_number"
	FormValueRememberMe   = "remember_me"
)

type HTTPBodyReader struct {
	ReadJSON    bool
	UseUsername bool
	Rulesets    map[string][]Rules
	Confirms    map[string][]string
	Whitelist   map[string][]string
}

func (h HTTPBodyReader) Read(page string, r *http.Request) (authboss.Validator, error) {
	var values map[string]string

	if h.ReadJSON {
		b, err := ioutil.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return nil, errors.Wrap(err, "failed to read http body")
		}

		if err = json.Unmarshal(b, &values); err != nil {
			return nil, errors.Wrap(err, "failed to parse json http body")
		}
	} else {
		if err := r.ParseForm(); err != nil {
			return nil, errors.Wrapf(err, "failed to parse form on page: %s", page)
		}
		values = defaults.URLValuesToMap(r.Form)
	}

	rules := h.Rulesets[page]
	confirms := h.Confirms[page]
	whitelist := h.Whitelist[page]

	switch page {
	case "confirm":
		return defaults.ConfirmValues{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules},
			Token:             values[FormValueConfirm],
		}, nil
	case "login":
		shouldRemember := values[FormValueRememberMe]
		var pid string
		if h.UseUsername {
			pid = values[FormValueUsername]
		} else {
			pid = values[FormValueEmail]
		}

		return RememberingUserValuers{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			PID:               pid,
			Password:          values[FormValuePassword],
			ShouldRemember:    shouldRemember,
		}, nil
	case "recover_start":
		var pid string
		if h.UseUsername {
			pid = values[FormValueUsername]
		} else {
			pid = values[FormValueEmail]
		}

		return defaults.RecoverStartValues{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			PID:               pid,
		}, nil
	case "recover_middle":
		return defaults.RecoverMiddleValues{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			Token:             values[FormValueToken],
		}, nil
	case "recover_end":
		return defaults.RecoverEndValues{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			Token:             values[FormValueToken],
			NewPassword:       values[FormValuePassword],
		}, nil
	case "totp2fa_confirm", "totp2fa_remove", "totp2fa_validate":
		return defaults.TwoFA{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			Code:              values[FormValueCode],
			RecoveryCode:      values[FormValueRecoveryCode],
		}, nil
	case "sms2fa_setup", "sms2fa_remove", "sms2fa_confirm", "sms2fa_validate":
		return defaults.SMSTwoFA{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			Code:              values[FormValueCode],
			PhoneNumber:       values[FormValuePhoneNumber],
			RecoveryCode:      values[FormValueRecoveryCode],
		}, nil
	case "register":
		arbitrary := make(map[string]string)

		for k, v := range values {
			for _, w := range whitelist {
				if k == w {
					arbitrary[k] = v
					break
				}
			}
		}

		var pid string
		if h.UseUsername {
			pid = values[FormValueUsername]
		} else {
			pid = values[FormValueEmail]
		}

		return defaults.UserValues{
			HTTPFormValidator: HTTPFormValidator{Values: values, Ruleset: rules, ConfirmFields: confirms},
			PID:               pid,
			Password:          values[FormValuePassword],
			Arbitrary:         arbitrary,
		}, nil
	default:
		return nil, errors.Errorf("failed to parse unknown page's form: %s", page)
	}
}

func NewHTTPBodyReader(usernameRule Rules, passwordRule Rules) HTTPBodyReader {
	return HTTPBodyReader{
		UseUsername: true,
		ReadJSON:    false,
		Rulesets: map[string][]Rules{
			"register": {usernameRule, passwordRule},
		},
		Confirms: map[string][]string{
			"register": {"password", "confirm_password"},
		},
		Whitelist: map[string][]string{
			"register": []string{"username", "password"},
		},
	}
}
