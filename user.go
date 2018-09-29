package security

import "time"

type User struct {
	Name string `json:"name" bson:"name"`

	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`

	OAuth2UID          string    `json:"oauth2uid" bson:"oauth2uid"`
	OAuth2Provider     string    `json:"oauth2provider" bson:"oauth2provider"`
	OAuth2AccessToken  string    `json:"oauth2accesstoken" bson:"oauth2accesstoken"`
	OAuth2RefreshToken string    `json:"oauth2refreshtoken" bson:"oauth2refreshtoken"`
	OAuth2Expiry       time.Time `json:"oauth2expiry" bson:"oauth2expiry"`
}

func (u *User) GetName() string {
	return u.Name
}

func (u *User) GetEmail() string {
	return u.Username
}

func (u *User) GetPID() string {
	return u.Username
}

func (u *User) GetPassword() string {
	return u.Password
}

func (u *User) IsOAuth2User() bool {
	return len(u.OAuth2UID) != 0
}

func (u *User) GetOAuth2UID() (uid string) {
	return u.OAuth2UID
}

func (u *User) GetOAuth2Provider() (provider string) {
	return u.OAuth2Provider
}

func (u *User) GetOAuth2AccessToken() (token string) {
	return u.OAuth2AccessToken
}

func (u *User) GetOAuth2RefreshToken() (refreshToken string) {
	return u.OAuth2RefreshToken
}

func (u *User) GetOAuth2Expiry() (expiry time.Time) {
	return u.OAuth2Expiry
}

func (u *User) GetArbitrary() map[string]string {
	return map[string]string{
		"name": u.Name,
	}
}

func (u *User) PutName(name string) {
	u.Name = name
}

func (u *User) PutEmail(email string) {
	u.Username = email
}

func (u *User) PutPID(pid string) {
	u.Username = pid
	u.Name = pid
}

func (u *User) PutPassword(password string) {
	u.Password = password
}

func (u *User) PutOAuth2UID(uid string) {
	u.OAuth2UID = uid
}

func (u *User) PutOAuth2Provider(provider string) {
	u.OAuth2Provider = provider
}

func (u *User) PutOAuth2AccessToken(token string) {
	u.OAuth2AccessToken = token
}

func (u *User) PutOAuth2RefreshToken(refreshToken string) {
	u.OAuth2RefreshToken = refreshToken
}

func (u *User) PutOAuth2Expiry(expiry time.Time) {
	u.OAuth2Expiry = expiry
}

func (u *User) PutArbitrary(values map[string]string) {
	if name, valueExists := values["name"]; valueExists {
		u.Name = name
	}
}
