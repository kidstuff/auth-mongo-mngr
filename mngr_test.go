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

	session.DB(dbname).DropDatabase()
}

func TestMain(t *testing.T) {
	dbname := "mgoauth_test_user_mannager"
	mngr := newManager(dbname)
	defer tearDown(dbname)

	uid := testManagerAddUser(t, mngr)

	gid := testManagerAddGroupDetail(t, mngr)

	testManagerUpdateUserDetail(t, mngr, uid, gid)
	testmanagerAddUserDetail(t, mngr, gid)
	// u2, err := mngr.AddUserDetail("user2@example.com", "zaq123edc", true,
	// 	nil, nil, nil, []string{*g1.Id})
	// if err != nil {
	// 	t.Fatal("cannot add new user with group:", err)
	// }

	// if len(u2.Groups) != 1 {
	// 	t.Fatal("missing group in user")
	// }

	// err = mngr.DeleteGroup(*g1.Id)
	// if err != nil {
	// 	t.Fatal("cannot delete group:", err)
	// }

	// u2b, err := mngr.FindUser(*u2.Id)
	// if err != nil {
	// 	t.Fatal("cannot find user:", err)
	// }

	// if len(u2b.Groups) != 0 {
	// 	t.Fatal("deletion of group must update group infomation of users")
	// }
}

func testManagerAddUser(t *testing.T, mngr authmodel.Manager) string {
	ps := "zaq123456"
	u1, err := mngr.AddUser("user1@example.com", ps, true)
	if err != nil {
		t.Fatal("cannot create new user:", err)
	}

	if u1.LastActivity != u1.Profile.JoinDay || u1.LastActivity == nil {
		t.Fatal("must initial the LastActivity and JoinDay")
	}

	_, err = mngr.AddUser("user1@example.com", ps, true)
	if err != authmodel.ErrDuplicateEmail {
		t.Fatal("must check for duplicate email:", err)
	}

	err = mngr.ComparePassword(ps, u1.Pwd)
	if err != nil {
		t.Fatal("password hash error:", err)
	}

	return *u1.Id
}

func testManagerUpdateUserDetail(t *testing.T, mngr authmodel.Manager, uid, gid string) {
	ps := "testing12345"
	app := false
	code := map[string]string{"tested": "notyet"}
	err := mngr.UpdateUserDetail(uid, &ps, &app, []string{"testing"}, code, nil, []string{gid})
	if err != nil {
		t.Fatal("cannot update user detail:", err)
	}

	u, err := mngr.FindUser(uid)
	if err != nil {
		t.Fatal("Cannot find user:", err)
	}

	if *u.Approved != app {
		t.Fatal("update user approved failed")
	}

	if len(u.Privileges) != 1 {
		t.Fatal("update user privileges failed")
	}

	if u.Privileges[0] != "testing" {
		t.Fatal("update user privileges failed")
	}

	if u.ConfirmCodes["tested"] != "notyet" {
		t.Fatal("update user confirm code failed")
	}

	if len(u.Groups) != 1 {
		t.Fatal("update user group failed")
	}

	if *u.Groups[0].Id != gid {
		t.Fatal("update user group failed")
	}

	err = mngr.ComparePassword(ps, u.Pwd)
	if err != nil {
		t.Fatal("password hash error:", err)
	}
}

func testmanagerAddUserDetail(t *testing.T, mngr authmodel.Manager, gid string) string {
	code := map[string]string{"tested": "notyet"}
	u, err := mngr.AddUserDetail("user2@example.com", "test123edc", true, []string{"testing"}, code, nil, []string{gid})
	if err != nil {
		t.Fatal("cannot update user detail:", err)
	}

	u, err = mngr.FindUser(*u.Id)
	if err != nil {
		t.Fatal("Cannot find user:", err)
	}

	if *u.Approved != true {
		t.Fatal("update user approved failed")
	}

	if len(u.Privileges) != 1 {
		t.Fatal("update user privileges failed")
	}

	if u.Privileges[0] != "testing" {
		t.Fatal("update user privileges failed")
	}

	if u.ConfirmCodes["tested"] != "notyet" {
		t.Fatal("update user confirm code failed")
	}

	if len(u.Groups) != 1 {
		t.Fatal("update user group failed")
	}

	if *u.Groups[0].Id != gid {
		t.Fatal("update user group failed")
	}

	return *u.Id
}

func testManagerAddGroupDetail(t *testing.T, mngr authmodel.Manager) string {
	info := authmodel.GroupInfo{}
	desc := "testing privelege"
	info.Description = &desc
	g1, err := mngr.AddGroupDetail("staff", []string{"testing"}, &info)
	if err != nil {
		t.Fatal("cannot create new group:", err)
	}

	_, err = mngr.AddGroupDetail("staff", nil, nil)
	if err == nil {
		t.Fatal("must check for duplicated group name")
	}

	g1, err = mngr.FindGroup(*g1.Id)
	if err != nil {
		t.Fatal("cannot created group:", err)
	}

	if len(g1.Privileges) != 1 {
		t.Fatal("add group privilege failed")
	}

	if g1.Privileges[0] != "testing" {
		t.Fatal("add group privilege failed")
	}

	if g1.Info == nil || g1.Info.Description == nil || *g1.Info.Description != desc {
		t.Fatal("add group info failed")
	}

	return *g1.Id
}
