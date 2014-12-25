package mgoauth_test

import (
	"github.com/kidstuff/auth-mongo-mngr"
	"github.com/kidstuff/auth/authmodel"
	"labix.org/v2/mgo"
	"testing"
	"time"
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

	uid2 := testManagerAddUserDetail(t, mngr, gid)
	testManagerDeleteGroup(t, mngr, gid, uid2)

	testManagerDeleteUser(t, mngr, uid)
	testManagerDeleteUser(t, mngr, uid2)

	gid = testManagerAddGroupDetail(t, mngr)
	testManagerFindAllUser(t, mngr, gid)

	testManagerLogin(t, mngr, testManagerAddUser(t, mngr))
}

// testManagerAddUser check if add user work
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

// testManagerUpdateUserDetail test update user operation and check the password hash function.
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

// testManagerAddUserDetail check if add user operation work
func testManagerAddUserDetail(t *testing.T, mngr authmodel.Manager, gid string) string {
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

// testManagerDeleteUser check if delete user operation work.
func testManagerDeleteUser(t *testing.T, mngr authmodel.Manager, uid string) {
	err := mngr.DeleteUser(uid)
	if err != nil {
		t.Fatal("delete user failed:", err)
	}

	_, err = mngr.FindUser(uid)
	if err != authmodel.ErrNotFound {
		t.Fatal("delete user not work")
	}
}

// testManagerFindAllUser add 10 users the do test about partial and projection select
func testManagerFindAllUser(t *testing.T, mngr authmodel.Manager, gid string) {
	users := make([]*authmodel.User, 10)
	var err error
	users[0], err = mngr.AddUser("test01@example.com", "testing123edc", true)
	if err != nil {
		t.Fatal("cannot add user", err)
	}

	users[1], err = mngr.AddUser("test02@example.com", "testing123edc", true)
	if err != nil {
		t.Fatal("cannot add user", err)
	}

	users[2], err = mngr.AddUser("test03@example.com", "testing123edc", true)
	if err != nil {
		t.Fatal("cannot add user", err)
	}

	users[3], err = mngr.AddUser("test04@example.com", "testing123edc", true)
	if err != nil {
		t.Fatal("cannot add user", err)
	}

	users[4], err = mngr.AddUser("test05@example.com", "testing123edc", true)
	if err != nil {
		t.Fatal("cannot add user", err)
	}

	users[5], err = mngr.AddUser("test06@example.com", "testing123edc", true)
	if err != nil {
		t.Fatal("cannot add user", err)
	}

	users[6], err = mngr.AddUser("test07@example.com", "testing123edc", true)
	if err != nil {
		t.Fatal("cannot add user", err)
	}

	users[7], err = mngr.AddUser("test08@example.com", "testing123edc", true)
	if err != nil {
		t.Fatal("cannot add user", err)
	}

	users[8], err = mngr.AddUserDetail("test09@example.com", "testing123edc", true, nil, nil, nil, []string{gid})
	if err != nil {
		t.Fatal("cannot add user", err)
	}

	users[9], err = mngr.AddUserDetail("test10@example.com", "testing123edc", true, nil, nil, nil, []string{gid})
	if err != nil {
		t.Fatal("cannot add user", err)
	}

	// get all user at the same time
	// should return the full list of 10 users
	userList, err := mngr.FindAllUser(-1, "", nil, nil)
	if n := len(userList); n != 10 {
		t.Fatal("get all user failed, expect 10 users, found", n)
	}

	// get all user belong to gid
	userList, err = mngr.FindAllUser(-1, "", nil, []string{gid})
	if n := len(userList); n != 2 {
		t.Fatal("get all user with groups id failed, expect 2 users, found", n)
	}

	// get a single user with specific feilds.
	userList, err = mngr.FindAllUser(1, "", []string{"Id", "Approved"}, nil)
	if n := len(userList); n != 1 {
		t.Fatal("get all user failed, expect 1 users, found", n)
	}

	if userList[0].Id == nil || userList[0].Approved == nil {
		t.Fatal("get all user failed retrieve specifiec fields")
	}

	if u := userList[0]; u.Email != nil || u.Pwd != nil || u.LastActivity != nil {
		t.Fatal("get all user failed not retrieved unspecific fields")
	}

	// get a part of user list
	userList1, err := mngr.FindAllUser(5, "", nil, nil)
	if n := len(userList1); n != 5 {
		t.Fatal("get all user failed, expect 5 but got", n)
	}

	// get the other part
	userList2, err := mngr.FindAllUser(5, *userList1[4].Id, nil, nil)
	if n := len(userList2); n != 5 {
		t.Fatal("get all user with offset id failed, expect 5 but got", n)
	}

	// and check if they are "paging" right
	for _, u1 := range userList1 {
		for _, u2 := range userList2 {
			if *u1.Id == *u2.Id {
				t.Fatal("get all user failed with limit and offset")
			}
		}
	}
}

// testManagerAddGroupDetail simply check if the create group operation work.
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

// testManagerDeleteGroup recieve a group id and a user id who belong to that group.
// After group delettion, check if the group infomation of in user account removed or not.
func testManagerDeleteGroup(t *testing.T, mngr authmodel.Manager, gid, uid string) {
	err := mngr.DeleteGroup(gid)
	if err != nil {
		t.Fatal("delete group failed:", err)
	}

	u, err := mngr.FindUser(uid)
	if err != nil {
		t.Fatal("cannot find user:", err)
	}

	if len(u.Groups) > 0 {
		t.Fatal("delete group must remove group info in user")
	}
}

// testManagerLogin login the same user by uid 3 times to get 3 different tokens.
// Then use them to test the Logout method.
func testManagerLogin(t *testing.T, mngr authmodel.Manager, uid string) {
	token, err := mngr.Login(uid, time.Minute)
	if err != nil {
		t.Fatal("cannot login:", err)
	}

	u, err := mngr.GetUser(token)
	if err != nil {
		t.Fatal("cannot get logged user:", err)
	}

	if *u.Id != uid {
		t.Fatal("loged user and user returned not the same")
	}

	token2, err := mngr.Login(uid, time.Minute)
	if err != nil {
		t.Fatal("cannot login:", err)
	}

	u, err = mngr.GetUser(token2)
	if err != nil {
		t.Fatal("cannot get logged user:", err)
	}

	if *u.Id != uid {
		t.Fatal("loged user and user returned not the same")
	}

	token3, err := mngr.Login(uid, time.Minute)
	if err != nil {
		t.Fatal("cannot login:", err)
	}

	u, err = mngr.GetUser(token3)
	if err != nil {
		t.Fatal("cannot get logged user:", err)
	}

	if *u.Id != uid {
		t.Fatal("loged user and user returned not the same")
	}

	if token == token2 || token2 == token3 || token == token3 {
		t.Fatal("token must not be the same")
	}

	err = mngr.Logout(token, false)
	if err != nil {
		t.Fatal("cannot logout user:", err)
	}

	u, err = mngr.GetUser(token)
	if err == nil || u != nil {
		t.Fatal("logout don't work")
	}

	err = mngr.Logout(token2, true)
	if err != nil {
		t.Fatal("cannot logout user:", err)
	}

	u, err = mngr.GetUser(token2)
	if err == nil || u != nil {
		t.Fatal("logout didn't work")
	}

	u, err = mngr.GetUser(token3)
	if err == nil || u != nil {
		t.Fatal("logout all user's session didn't work")
	}
}
