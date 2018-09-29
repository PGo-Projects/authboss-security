package database

import (
	"github.com/globalsign/mgo"
)

var (
	Manager *DBManager
)

func init() {
	if Manager == nil {
		Manager = mustInitDBManager("127.0.0.1:27017")
	}
}

type DBManager struct {
	session *mgo.Session
}

func mustInitDBManager(addresses ...string) *DBManager {
	session, err := mgo.DialWithInfo(&mgo.DialInfo{
		Addrs: addresses,
	})

	if err != nil {
		panic(err)
	}

	return &DBManager{session: session}
}

func (db *DBManager) Create(name string) *mgo.Database {
	return db.session.DB(name)
}

func (db *DBManager) Close() {
	db.session.Close()
}
