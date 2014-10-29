package mgoauth_test

import (
	"github.com/kidstuff/auth-mongo-mngr"
	"github.com/kidstuff/auth/model"
	"labix.org/v2/mgo"
)

func NewGroupManager(dbname string) model.GroupManager {
	session, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	session.SetMode(mgo.Monotonic, true)

	return mgoauth.NewMgoGroupManager(session.DB(dbname))
}
