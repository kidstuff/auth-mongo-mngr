package mgoauth

import (
	"github.com/kidstuff/auth/model"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

type MgoConfigMngr struct {
	ConfigColl *mgo.Collection
}

func NewMgoConfigMngr(db *mgo.Database) *MgoConfigMngr {
	return &MgoConfigMngr{db.C("mgoconfig")}
}

func (c *MgoConfigMngr) Set(key string, val string) error {
	return c.SetMulti([]*model.ConfigObj{&model.ConfigObj{&key, &val}})
}

func (c *MgoConfigMngr) SetMulti(objs []*model.ConfigObj) error {
	for _, obj := range objs {
		_, err := c.ConfigColl.UpsertId(*obj.Key, bson.M{
			"$set": bson.M{"Val": *obj},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *MgoConfigMngr) UnSet(key string) error {
	return c.UnSetMulti([]string{key})
}

func (c *MgoConfigMngr) UnSetMulti(key []string) error {
	_, err := c.ConfigColl.RemoveAll(bson.M{"_id": bson.M{"$in": key}})
	return err
}

func (c *MgoConfigMngr) Get(key string) (string, error) {
	objs, err := c.GetMulti([]string{key})
	if len(objs) == 1 {
		return *objs[0].Val, nil
	}

	return "", err
}

func (c *MgoConfigMngr) GetMulti(key []string) ([]*model.ConfigObj, error) {
	result := make([]*model.ConfigObj, 0, len(key))
	err := c.ConfigColl.Find(bson.M{"_id": bson.M{"$in": key}}).All(&result)

	return result, err
}
