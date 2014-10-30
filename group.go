package mgoauth

import (
	"github.com/kidstuff/auth/authmodel"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

type Group struct {
	Id              bson.ObjectId `bson:"_id"`
	authmodel.Group `bson:",inline"`
}

func (m *MgoManager) AddGroupDetail(name string, pri []string, info *authmodel.GroupInfo) (*authmodel.Group, error) {
	group := &Group{}
	group.Id = bson.NewObjectId()
	sid := group.Id.Hex()
	group.Group.Id = &sid
	group.Name = &name
	group.Privilege = pri
	group.Info = info
	if group.Name == nil {
		return nil, authmodel.ErrInvalidEmail
	}

	err := m.GroupColl.Insert(group)
	if err != nil {
		if mgo.IsDup(err) {
			return nil, authmodel.ErrDuplicateName
		}
		return nil, err
	}

	return &group.Group, nil
}

func (m *MgoManager) UpdateGroupDetail(id string, pri []string, info *authmodel.GroupInfo) error {
	oid, err := getId(id)
	if err != nil {
		return err
	}

	change := bson.M{}
	if info != nil {
		change["Info"] = *info
	}
	if pri != nil {
		change["Privilege"] = pri
	}

	return m.GroupColl.UpdateId(oid, bson.M{"$set": change})
}

func (m *MgoManager) FindGroup(id string) (*authmodel.Group, error) {
	oid, err := getId(id)
	if err != nil {
		return nil, err
	}

	group := &authmodel.Group{}
	err = m.GroupColl.FindId(oid).One(group)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (m *MgoManager) FindGroupByName(name string) (*authmodel.Group, error) {
	group := &authmodel.Group{}
	err := m.GroupColl.Find(bson.M{"Name": name}).One(group)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (m *MgoManager) FindSomeGroup(id ...string) (
	[]*authmodel.Group, error) {
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

	groups := make([]*authmodel.Group, 0, len(aid))
	err := m.GroupColl.Find(bson.M{"_id": bson.M{"$in": aid}}).All(&groups)
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func (m *MgoManager) FindAllGroup(limit int, offsetId string, fields []string) (
	[]*authmodel.Group, error) {
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

	var groups []*authmodel.Group
	if limit > 0 {
		query.Limit(limit)
		groups = make([]*authmodel.Group, 0, limit)
	} else {
		groups = []*authmodel.Group{}
	}

	err = query.All(&groups)

	if err != nil {
		return nil, err
	}

	return groups, nil

}

func (m *MgoManager) DeleteGroup(id string) error {
	oid, err := getId(id)
	if err != nil {
		return err
	}
	// TODO: remove this group form user briefgroups too?
	return m.GroupColl.RemoveId(oid)
}
