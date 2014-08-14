package mgoauth

import (
	"github.com/kidstuff/conf"
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
	return c.SetMulti(map[string]string{key: val})
}

func (c *MgoConfigMngr) SetMulti(m map[string]string) error {
	for key, val := range m {
		_, err := c.ConfigColl.UpsertId(key, bson.M{
			"$set": bson.M{"Val": val},
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

func (c *MgoConfigMngr) UnSetMulti(keys []string) error {
	_, err := c.ConfigColl.RemoveAll(bson.M{"_id": bson.M{"$in": keys}})
	return err
}

func (c *MgoConfigMngr) Get(key string) (string, error) {
	m, err := c.GetMulti([]string{key})
	if len(m[key]) > 0 {
		return m[key], nil
	}

	return "", err
}

func (c *MgoConfigMngr) GetMulti(keys []string) (map[string]string, error) {
	result := make([]*conf.ConfigObj, 0, len(keys))
	err := c.ConfigColl.Find(bson.M{"_id": bson.M{"$in": keys}}).All(&result)
	if err != nil {
		return nil, err
	}

	m := make(map[string]string)
	for _, obj := range result {
		m[*obj.Key] = *obj.Val
	}

	return m, err
}
