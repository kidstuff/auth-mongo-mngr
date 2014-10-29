package mgoauth_test

import (
	"github.com/kidstuff/auth-mongo-mngr"
	"github.com/kidstuff/auth/model"
	"labix.org/v2/mgo"
	"testing"
)

func NewUserManager(dbname string) model.UserManager {
	session, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	session.SetMode(mgo.Monotonic, true)
	db := session.DB(dbname)

	mgoauth.EnsureIndex(db)
	return mgoauth.NewMgoUserManager(db, NewGroupManager(dbname))
}

func tearDown(dbname string) {
	session, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)

	session.DB(dbname).DropDatabase()
}

func TestMgoUserManager(t *testing.T) {
	dbname := "mgoauth_test_user_mannager"
	mngr := NewUserManager(dbname)
	defer tearDown(dbname)

	u1, err := mngr.Add("user1@example.com", "zaq123456", true)
	if err != nil {
		t.Fatal("cannot creat new user:", err)
	}

	if u1.LastActivity != u1.Profile.JoinDay || u1.LastActivity == nil {
		t.Fatal("must initial the LastActivity and JoinDay")
	}

	_, err = mngr.Add("user1@example.com", "zaq123456", true)
	if err != model.ErrDuplicateEmail {
		t.Fatal("must check for duplicate email")
	}

	u1b, err := mngr.Find(*u1.Id)
	if err != nil || *u1.Email != *u1b.Email {
		t.Fatal("cannot find user by Id")
	}
}
