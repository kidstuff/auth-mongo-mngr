package mgoauth

import (
	"github.com/kidstuff/auth/model"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

type MgoGroupManager struct {
	GroupColl    *mgo.Collection
	DefaultLimit int
}

type Group struct {
	Id          bson.ObjectId `bson:"_id"`
	model.Group `bson:",inline"`
}

func NewMgoGroupManager(db *mgo.Database) *MgoGroupManager {
	mngr := &MgoGroupManager{}
	mngr.GroupColl = db.C("mgoauth_group")
	mngr.DefaultLimit = 500
	return mngr
}

func (m *MgoGroupManager) AddDetail(g *model.Group) (*model.Group, error) {
	group := &Group{}
	group.Id = bson.NewObjectId()
	sid := group.Id.Hex()
	group.Group = *g
	group.Group.Id = &sid
	if group.Name == nil {
		return nil, model.ErrInvalidEmail
	}

	err := m.GroupColl.Insert(group)
	if err != nil {
		if mgo.IsDup(err) {
			return nil, model.ErrDuplicateName
		}
		return nil, err
	}

	return &group.Group, nil
}

func (m *MgoGroupManager) UpdateDetail(group *model.Group) error {
	oid, err := getId(*group.Id)
	if err != nil {
		return err
	}

	change := bson.M{}
	if group.Info != nil {
		change["Info"] = *group.Info
	}
	if group.Privilege != nil {
		change["Privilege"] = group.Privilege
	}

	return m.GroupColl.UpdateId(oid, bson.M{"$set": change})
}

func (m *MgoGroupManager) Find(id string) (*model.Group, error) {
	oid, err := getId(id)
	if err != nil {
		return nil, err
	}

	group := &model.Group{}
	err = m.GroupColl.FindId(oid).One(group)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (m *MgoGroupManager) FindByName(name string) (*model.Group, error) {
	group := &model.Group{}
	err := m.GroupColl.Find(bson.M{"Name": name}).One(group)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (m *MgoGroupManager) FindSome(id ...string) (
	[]*model.Group, error) {
	aid := make([]bson.ObjectId, 0, len(id))
	for _, v := range id {
		oid, err := getId(v)
		if err != nil {
			continue
		}
		aid = append(aid, oid)
	}

	if len(aid) == 0 {
		return nil, ErrNoResult
	}

	groups := make([]*model.Group, 0, len(aid))
	err := m.GroupColl.Find(bson.M{"_id": bson.M{"$in": aid}}).All(&groups)
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func (m *MgoGroupManager) FindAll(limit int, offsetId string, fields []string) (
	[]*model.Group, error) {
	if limit == 0 {
		return nil, ErrNoResult
	}

	if limit > m.DefaultLimit || limit < 0 {
		limit = m.DefaultLimit
	}

	filter := bson.M{}
	oid, err := getId(offsetId)
	if err == nil {
		filter["_id"] = bson.M{"$gt": oid}
	}

	query := m.GroupColl.Find(filter).Sort("_id")
	if len(fields) > 0 {
		selector := make(bson.M)
		for _, f := range fields {
			selector[f] = 1
		}
		query.Select(selector)
	}

	var groups []*model.Group
	if limit > 0 {
		query.Limit(limit)
		groups = make([]*model.Group, 0, limit)
	} else {
		groups = []*model.Group{}
	}

	err = query.All(&groups)

	if err != nil {
		return nil, err
	}

	return groups, nil

}

func (m *MgoGroupManager) Delete(id string) error {
	oid, err := getId(id)
	if err != nil {
		return err
	}
	// TODO: remove this group form user briefgroups too?
	return m.GroupColl.RemoveId(oid)
}
