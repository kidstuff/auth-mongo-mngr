package mgoauth

import (
	"github.com/kidstuff/auth/model"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"time"
)

type LoginState struct {
	ExpiredOn time.Time     `bson:"ExpiredOn"`
	UserId    bson.ObjectId `bson:"UserId"`
	Token     string        `bson:"_id"`
}

// getId returns bson.ObjectId form given id.
// id must be a valid bson.ObjectId or a valid ObjectIdHex
func getId(id interface{}) (bson.ObjectId, error) {
	oid, ok := id.(bson.ObjectId)
	if ok {
		return oid, nil
	}

	sid, ok := id.(string)
	if !ok || !bson.IsObjectIdHex(sid) {
		return "", model.ErrInvalidId
	}

	return bson.ObjectIdHex(sid), nil
}

func _IdToString(id interface{}) (string, error) {
	oid, err := getId(id)
	if err != nil {
		return "", err
	}

	return oid.Hex(), nil
}

func _IdFromString(s string) (interface{}, error) {
	if bson.IsObjectIdHex(s) {
		return bson.ObjectIdHex(s), nil
	}

	return "", nil
}

func EqualIdChecker(id interface{}, sid string) bool {
	oid, err := getId(id)
	if err != nil {
		return false
	}

	return oid.Hex() == sid
}

// EnsureIndex builds the index for users data and login state collection.
func EnsureIndex(db *mgo.Database) error {
	groupColl := db.C("mgoauth_group")
	userColl := db.C("mgoauth_user")
	loginColl := db.C("mgoauth_login")

	err := userColl.EnsureIndex(mgo.Index{
		Key:    []string{"Email"},
		Unique: true,
	})
	if err != nil {
		return err
	}

	err = userColl.EnsureIndexKey("LastActivity")
	if err != nil {
		return err
	}

	err = userColl.EnsureIndexKey("BriefGroups._id")
	if err != nil {
		return err
	}

	err = loginColl.EnsureIndex(mgo.Index{
		Key:      []string{"UserId"},
		DropDups: true,
	})
	if err != nil {
		return err
	}

	err = loginColl.EnsureIndex(mgo.Index{
		Key:         []string{"ExpiredOn"},
		ExpireAfter: time.Minute,
	})

	err = groupColl.EnsureIndex(mgo.Index{
		Key:    []string{"Name"},
		Unique: true,
	})

	return nil
}
