package mgoauth

import (
	"code.google.com/p/go.crypto/bcrypt"
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

type User struct {
	Id         bson.ObjectId `bson:"_id"`
	model.User `bson:",inline"`
}

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

func hashPwd(pwd string) (model.Password, error) {
	p := model.Password{}
	p.InitAt = time.Now()
	p.Salt = securecookie.GenerateRandomKey(32)

	pwdBytes := []byte(pwd)
	tmp := make([]byte, len(pwdBytes)+len(p.Salt))
	copy(tmp, pwdBytes)
	tmp = append(tmp, p.Salt...)
	b, err := bcrypt.GenerateFromPassword(tmp, bcrypt.DefaultCost)
	p.Hashed = b

	return p, err
}

func (m *MgoUserManager) newUser(email, pwd string, app bool) (*User, error) {
	if !m.Formater.EmailValidate(email) {
		return nil, model.ErrInvalidEmail
	}

	if !m.Formater.PasswordValidate(pwd) {
		return nil, model.ErrInvalidPassword
	}

	u := &User{}
	u.Id = bson.NewObjectId()
	sid := u.Id.Hex()
	u.User.Id = &sid
	u.Email = &email
	now := time.Now()
	u.LastActivity = &now
	u.Profile = &model.Profile{}
	u.Profile.JoinDay = u.LastActivity

	p, err := hashPwd(pwd)
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

func (m *MgoUserManager) insertUser(u *User) error {
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

	return &u.User, nil
}

func (m *MgoUserManager) AddDetail(email, pwd string, app bool, pri []string,
	code map[string]string, profile *model.Profile, groups []model.Group) (*model.User, error) {
	u, err := m.newUser(email, pwd, app)
	if err != nil {
		return nil, err
	}
	u.Privilege = pri
	u.ConfirmCodes = code
	u.Profile = profile
	u.Groups = groups

	err = m.insertUser(u)
	if err != nil {
		return nil, err
	}

	return &u.User, nil
}

func (m *MgoUserManager) UpdateDetail(id string, pwd *string, app *bool, pri []string,
	code map[string]string, profile *model.Profile, groups []model.Group) error {
	if !bson.IsObjectIdHex(id) {
		return model.ErrInvalidId
	}
	oid := bson.ObjectIdHex(id)

	changes := make(bson.M)
	if pri != nil {
		changes["Privilege"] = pri
	}
	if code != nil {
		changes["ConfirmCodes"] = code
	}
	if groups != nil {
		changes["Groups"] = groups
	}
	if app != nil {
		changes["Approved"] = *app
	}
	if profile != nil {
		changes["Profile"] = profile
	}
	if pwd != nil {
		changes["Pwd"] = *pwd
	}

	return m.UserColl.UpdateId(oid, bson.M{"$set": changes})
}

func (m *MgoUserManager) Delete(id string) error {
	oid, err := getId(id)
	if err != nil {
		return err
	}

	return m.UserColl.RemoveId(oid)
}

func (m *MgoUserManager) Find(id string) (*model.User, error) {
	oid, err := getId(id)
	if err != nil {
		return nil, err
	}

	user := &model.User{}
	err = m.UserColl.FindId(oid).One(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (m *MgoUserManager) FindByEmail(email string) (*model.User, error) {
	if !m.Formater.EmailValidate(email) {
		return nil, model.ErrInvalidEmail
	}

	user := &model.User{}
	err := m.UserColl.Find(bson.M{"Email": email}).One(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (m *MgoUserManager) findAll(limit int, offsetId string, fields []string,
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

	if bson.IsObjectIdHex(offsetId) {
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

	var users []*model.User
	if limit > 0 {
		query.Limit(limit)
		users = make([]*model.User, 0, limit)
	} else {
		users = []*model.User{}
	}

	err := query.All(&users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (m *MgoUserManager) FindAll(limit int, offsetId string, fields []string) (
	[]*model.User, error) {
	return m.findAll(limit, offsetId, fields, nil)
}

func (m *MgoUserManager) FindAllOnline(limit int, offsetId string, fields []string) (
	[]*model.User, error) {
	return m.findAll(limit, offsetId, fields, bson.M{
		"LastActivity": bson.M{"$lt": time.Now().Add(m.MinimumOnlineThreshold)},
	})
}

func (m *MgoUserManager) updateLastActivity(id bson.ObjectId) (*model.User, error) {
	user := &model.User{}
	err := m.UserColl.FindId(id).One(user)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	user.LastActivity = &now
	// ??? should we ignore the error return here?
	err = m.UserColl.UpdateId(id, bson.M{
		"$set": bson.M{"LastActivity": *user.LastActivity},
	})
	if err != nil {
		return nil, err
	}

	return user, nil
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

func (m *MgoUserManager) Login(id string, stay time.Duration) (string, error) {
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

func (m *MgoUserManager) ComparePassword(ps string, pwd *model.Password) error {
	pwdBytes := []byte(ps)
	tmp := make([]byte, len(pwdBytes)+len(pwd.Salt))
	copy(tmp, pwdBytes)
	tmp = append(tmp, pwd.Salt...)
	if err := bcrypt.CompareHashAndPassword(pwd.Hashed, tmp); err != nil {
		return err
	}

	return nil
}
