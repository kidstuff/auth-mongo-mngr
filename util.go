package mgoauth

import (
	"github.com/kidstuff/auth/authmodel"
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
func getId(id string) (bson.ObjectId, error) {
	if !bson.IsObjectIdHex(id) {
		return "", authmodel.ErrInvalidId
	}

	return bson.ObjectIdHex(id), nil
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

	err = userColl.EnsureIndexKey("Groups.Id")
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

// Setup run EnsureIndex and stuff to prepare database
func Setup(db *mgo.Database) error {
	return EnsureIndex(db)
}
