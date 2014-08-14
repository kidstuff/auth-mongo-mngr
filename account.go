package mgoauth

import (
	"encoding/base64"
	"errors"
	"github.com/gorilla/securecookie"
	"github.com/kidstuff/auth/model"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"strings"
	"time"
)

var (
	ErrNoResult = errors.New("mgoauth: no result")
)

type MgoUserManager struct {
	MinimumOnlineThreshold time.Duration
	UserColl               *mgo.Collection
	LoginColl              *mgo.Collection
	Formater               model.FormatChecker
	GroupMngr              model.GroupManager
	DefaultLimit           int
}

func NewMgoUserManager(db *mgo.Database, groupMngr model.GroupManager) *MgoUserManager {
	mngr := &MgoUserManager{
		UserColl:               db.C("mgoauth_user"),
		LoginColl:              db.C("mgoauth_login"),
		MinimumOnlineThreshold: time.Minute * 5,
		GroupMngr:              groupMngr,
		DefaultLimit:           500,
	}

	mngr.Formater, _ = model.NewSimpleChecker(9)

	return mngr
}

func (m *MgoUserManager) newUser(email, pwd string, app bool) (*model.User, error) {
	if !m.Formater.EmailValidate(email) {
		return nil, model.ErrInvalidEmail
	}

	if !m.Formater.PasswordValidate(pwd) {
		return nil, model.ErrInvalidPassword
	}

	u := &model.User{}
	u.Id = bson.NewObjectId()
	u.Email = &email
	now := time.Now()
	u.LastActivity = &now
	u.Info = &model.UserInfo{}
	u.Info.JoinDay = u.LastActivity

	p, err := model.HashPwd(pwd)
	if err != nil {
		return nil, err
	}

	u.Pwd = &p

	u.Approved = &app
	if !app {
		u.ConfirmCodes = map[string]string{
			"activate": strings.Trim(base64.URLEncoding.
				EncodeToString(securecookie.GenerateRandomKey(64)), "="),
		}
	}

	return u, nil
}

func (m *MgoUserManager) insertUser(u *model.User) error {
	err := m.UserColl.Insert(u)
	if err != nil {
		if mgo.IsDup(err) {
			return model.ErrDuplicateEmail
		}
		return err
	}

	return nil
}

func (m *MgoUserManager) Add(email, pwd string, app bool) (*model.User,
	error) {
	u, err := m.newUser(email, pwd, app)
	if err != nil {
		return nil, err
	}

	err = m.insertUser(u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (m *MgoUserManager) AddDetail(u *model.User) (*model.User, error) {
	u.Id = bson.NewObjectId()
	err := m.insertUser(u)
	return u, err
}

func (m *MgoUserManager) UpdateDetail(u *model.User) error {
	oid, err := getId(u.Id)
	if err != nil {
		return err
	}

	changes := make(bson.M)
	if u.Privilege != nil {
		changes["Privilege"] = u.Privilege
	}
	if u.ConfirmCodes != nil {
		changes["ConfirmCodes"] = u.ConfirmCodes
	}
	if u.BriefGroups != nil {
		changes["BriefGroups"] = u.BriefGroups
	}
	if u.Approved != nil {
		changes["Approved"] = *u.Approved
	}
	if u.Info != nil {
		changes["Info"] = *u.Info
	}

	return m.UserColl.UpdateId(oid, bson.M{"$set": changes})
}

func (m *MgoUserManager) Delete(id interface{}) error {
	oid, err := getId(id)
	if err != nil {
		return err
	}

	return m.UserColl.RemoveId(oid)
}

func (m *MgoUserManager) Find(id interface{}) (*model.User, error) {
	oid, err := getId(id)
	if err != nil {
		return nil, err
	}

	u := &model.User{}
	err = m.UserColl.FindId(oid).One(u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (m *MgoUserManager) FindByEmail(email string) (*model.User, error) {
	if !m.Formater.EmailValidate(email) {
		return nil, model.ErrInvalidEmail
	}

	u := &model.User{}
	err := m.UserColl.Find(bson.M{"Email": email}).One(u)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (m *MgoUserManager) findAll(limit int, offsetId interface{}, fields []string,
	filter bson.M) ([]*model.User, error) {
	if limit == 0 {
		return nil, ErrNoResult
	}

	if limit > m.DefaultLimit || limit < 0 {
		limit = m.DefaultLimit
	}

	if filter == nil {
		filter = bson.M{}
	}

	if offsetId != nil {
		oid, err := getId(offsetId)
		if err == nil {
			filter["_id"] = bson.M{"$gt": oid}
		}
	}

	query := m.UserColl.Find(filter)
	if len(fields) > 0 {
		selector := make(bson.M)
		for _, f := range fields {
			selector[f] = 1
		}
		query.Select(selector)
	}

	var accounts []*model.User
	if limit > 0 {
		query.Limit(limit)
		accounts = make([]*model.User, 0, limit)
	} else {
		accounts = []*model.User{}
	}

	err := query.All(&accounts)
	if err != nil {
		return nil, err
	}

	return accounts, nil
}

func (m *MgoUserManager) FindAll(limit int, offsetId interface{}, fields []string) (
	[]*model.User, error) {
	return m.findAll(limit, offsetId, fields, nil)
}

func (m *MgoUserManager) FindAllOnline(limit int, offsetId interface{}, fields []string) (
	[]*model.User, error) {
	return m.findAll(limit, offsetId, fields, bson.M{
		"LastActivity": bson.M{"$lt": time.Now().Add(m.MinimumOnlineThreshold)},
	})
}

func (m *MgoUserManager) updateLastActivity(id bson.ObjectId) (*model.User, error) {
	u := &model.User{}
	err := m.UserColl.FindId(id).One(u)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	u.LastActivity = &now
	// ??? should we ignore the error return here?
	err = m.UserColl.UpdateId(id, bson.M{
		"$set": bson.M{"LastActivity": *u.LastActivity},
	})
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (m *MgoUserManager) Get(token string) (*model.User, error) {
	state := LoginState{}
	err := m.LoginColl.FindId(token).One(&state)
	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, model.ErrNotLogged
		}
		return nil, err
	}

	if !state.ExpiredOn.After(time.Now()) {
		m.LoginColl.RemoveId(token)
	}

	return m.updateLastActivity(state.UserId)
}

func (m *MgoUserManager) Login(id interface{}, stay time.Duration) (string, error) {
	if stay < m.MinimumOnlineThreshold {
		stay = m.MinimumOnlineThreshold
	}

	oid, err := getId(id)
	if err != nil {
		return "", err
	}

	state := LoginState{
		ExpiredOn: time.Now().Add(stay),
		UserId:    oid,
		Token: oid.Hex() + base64.URLEncoding.
			EncodeToString(securecookie.GenerateRandomKey(64)),
	}

	err = m.LoginColl.Insert(&state)
	if err != nil {
		return "", err
	}

	return state.Token, nil
}

func (m *MgoUserManager) Logout(token string) error {
	return m.LoginColl.RemoveId(token)
}
