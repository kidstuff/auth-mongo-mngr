package mgoauth_test

import (
	"github.com/kidstuff/auth-mongo-mngr"
	"github.com/kidstuff/auth/authmodel"
	"labix.org/v2/mgo"
	"testing"
)

func newManager(dbname string) authmodel.Manager {
	session, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	session.SetMode(mgo.Monotonic, true)
	db := session.DB(dbname)

	mgoauth.EnsureIndex(db)
	return mgoauth.NewMgoManager(db)
}

func tearDown(dbname string) {
	session, err := mgo.Dial("localhost")
	if err != nil {
		panic(err)
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)

	//session.DB(dbname).DropDatabase()
}

func TestMain(t *testing.T) {
	dbname := "mgoauth_test_user_mannager"
	mngr := newManager(dbname)
	defer tearDown(dbname)

	u1, err := mngr.AddUser("user1@example.com", "zaq123456", true)
	if err != nil {
		t.Fatal("cannot create new user:", err)
	}

	if u1.LastActivity != u1.Profile.JoinDay || u1.LastActivity == nil {
		t.Fatal("must initial the LastActivity and JoinDay")
	}

	_, err = mngr.AddUser("user1@example.com", "zaq123456", true)
	if err != authmodel.ErrDuplicateEmail {
		t.Fatal("must check for duplicate email:", err)
	}

	u1b, err := mngr.FindUser(*u1.Id)
	if err != nil || *u1.Email != *u1b.Email {
		t.Fatal("cannot find user by Id:", err)
	}

	g1, err := mngr.AddGroupDetail("staff", nil, nil)
	if err != nil {
		t.Fatal("cannot create new group:", err)
	}

	u2, err := mngr.AddUserDetail("user2@example.com", "zaq123edc", true,
		nil, nil, nil, []string{*g1.Id})
	if err != nil {
		t.Fatal("cannot add new user with group:", err)
	}

	if len(u2.Groups) != 1 {
		t.Fatal("missing group in user")
	}

	err = mngr.DeleteGroup(*g1.Id)
	if err != nil {
		t.Fatal("cannot delete group:", err)
	}

	u2b, err := mngr.FindUser(*u2.Id)
	if err != nil {
		t.Fatal("cannot find user:", err)
	}

	if len(u2b.Groups) != 0 {
		t.Fatal("deletion of group must update group infomation of users")
	}
}
