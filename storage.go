package security

import (
	"context"

	"github.com/PGo-Projects/authboss-security/database"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
	aboauth "github.com/volatiletech/authboss/oauth2"
)

type CredentialsStorage struct {
	backendDB *mgo.Database
	security  *mgo.Collection
}

func NewCredentialsStorage(dbName string) *CredentialsStorage {
	backendDB := database.Manager.Create(dbName)
	return &CredentialsStorage{
		backendDB: backendDB,
		security:  backendDB.C("security"),
	}
}

func (cs *CredentialsStorage) New(ctx context.Context) authboss.User {
	return &User{}
}

func (cs *CredentialsStorage) Create(ctx context.Context, user authboss.User) error {
	u := user.(*User)

	query := bson.M{"username": user.GetPID()}
	if count, err := cs.security.Find(query).Count(); err == nil && count == 0 {
		cs.security.Insert(u)
		return nil
	}
	return authboss.ErrUserFound
}

func (cs *CredentialsStorage) Save(ctx context.Context, user authboss.User) error {
	u := user.(*User)
	updateQuery := bson.M{"username": u.GetPID()}
	if err := cs.security.Update(updateQuery, u); err != nil {
		return authboss.ErrUserNotFound
	}
	return nil
}

func (cs *CredentialsStorage) Load(ctx context.Context, key string) (user authboss.User, err error) {
	var u *User

	provider, uid, err := authboss.ParseOAuth2PID(key)
	if err == nil {
		query := bson.M{"oauth2provider": provider, "oauth2uid": uid}
		err = cs.security.Find(query).One(&u)
		if err != nil {
			return nil, authboss.ErrUserNotFound
		}
		return u, nil
	}

	query := bson.M{"username": key}
	err = cs.security.Find(query).One(&u)
	if err != nil {
		return nil, authboss.ErrUserNotFound
	}
	return u, nil
}

func (cs *CredentialsStorage) AddRememberToken(ctx context.Context, pid string, token string) error {
	query := bson.M{"remember_token_username": pid, "remember_token": token}
	err := cs.security.Insert(query)
	return err
}

func (cs *CredentialsStorage) DelRememberTokens(ctx context.Context, pid string) error {
	query := bson.M{"remember_token_username": pid}
	_, err := cs.security.RemoveAll(query)
	return err
}

func (cs *CredentialsStorage) UseRememberToken(ctx context.Context, pid string, token string) error {
	query := bson.M{"remember_token_username": pid, "remember_token": token}
	changeInfo, err := cs.security.RemoveAll(query)
	if err != nil || changeInfo.Removed == 0 {
		return authboss.ErrTokenNotFound
	}
	return nil
}

func (cs *CredentialsStorage) NewFromOAuth2(ctx context.Context, provider string, details map[string]string) (authboss.OAuth2User, error) {
	switch provider {
	case "google":
		email := details[aboauth.OAuth2Email]

		var user *User
		query := bson.M{"username": email}
		err := cs.security.Find(query).One(&user)
		if err != nil {
			user = &User{}
		}

		user.PutName(details[aboauth.OAuth2Name])
		user.PutOAuth2UID(details[aboauth.OAuth2UID])
		user.PutEmail(email)
		return user, nil
	}
	return nil, errors.Errorf("unknown provider %s", provider)
}

func (cs *CredentialsStorage) SaveOAuth2(ctx context.Context, user authboss.OAuth2User) error {
	u := user.(*User)
	updateQuery := bson.M{"username": u.GetEmail()}
	_, err := cs.security.Upsert(updateQuery, u)
	return err
}
