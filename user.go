package mgoauth

import (
	"code.google.com/p/go.crypto/bcrypt"
	"encoding/base64"
	"errors"
	"github.com/gorilla/securecookie"
	"github.com/kidstuff/auth/authmodel"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"strings"
	"time"
)

var (
	ErrNoResult = errors.New("mgoauth: no result")
)

type User struct {
	Id             bson.ObjectId `bson:"_id"`
	authmodel.User `bson:",inline"`
}

type MgoManager struct {
	MinimumOnlineThreshold time.Duration
	GroupColl              *mgo.Collection
	UserColl               *mgo.Collection
	LoginColl              *mgo.Collection
	Formater               authmodel.FormatChecker
	DefaultLimit           int
}

func NewMgoManager(db *mgo.Database) *MgoManager {
	mngr := &MgoManager{
		GroupColl:              db.C("mgoauth_group"),
		UserColl:               db.C("mgoauth_user"),
		LoginColl:              db.C("mgoauth_login"),
		MinimumOnlineThreshold: time.Minute * 5,
		DefaultLimit:           500,
	}

	mngr.Formater, _ = authmodel.NewSimpleChecker(9)

	return mngr
}

func hashPwd(pwd string) (authmodel.Password, error) {
	p := authmodel.Password{}
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

func (m *MgoManager) newUser(email, pwd string, app bool) (*User, error) {
	if !m.Formater.EmailValidate(email) {
		return nil, authmodel.ErrInvalidEmail
	}

	if !m.Formater.PasswordValidate(pwd) {
		return nil, authmodel.ErrInvalidPassword
	}

	u := &User{}
	u.Id = bson.NewObjectId()
	sid := u.Id.Hex()
	u.User.Id = &sid
	u.Email = &email

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

func (m *MgoManager) insertUser(u *User) error {
	now := time.Now()
	u.LastActivity = &now
	if u.Profile == nil {
		u.Profile = &authmodel.Profile{}
	}
	u.Profile.JoinDay = u.LastActivity

	err := m.UserColl.Insert(u)
	if err != nil {
		if mgo.IsDup(err) {
			return authmodel.ErrDuplicateEmail
		}
		return err
	}

	return nil
}

func (m *MgoManager) AddUser(email, pwd string, app bool) (*authmodel.User,
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

func (m *MgoManager) AddUserDetail(email, pwd string, app bool, pri []string,
	code map[string]string, profile *authmodel.Profile, groupIds []string) (*authmodel.User, error) {
	u, err := m.newUser(email, pwd, app)
	if err != nil {
		return nil, err
	}
	u.Privileges = pri
	u.ConfirmCodes = code
	u.Profile = profile
	if groupIds != nil {
		groups, err := m.FindSomeGroup(groupIds, []string{"Id", "Name"})
		if err == nil {
			u.Groups = groups
		}
	}

	err = m.insertUser(u)
	if err != nil {
		return nil, err
	}

	return &u.User, nil
}

func (m *MgoManager) UpdateUserDetail(id string, pwd *string, app *bool, pri []string,
	code map[string]string, profile *authmodel.Profile, groupIds []string) error {
	if !bson.IsObjectIdHex(id) {
		return authmodel.ErrInvalidId
	}
	oid := bson.ObjectIdHex(id)

	changes := make(bson.M)
	if pri != nil {
		changes["Privileges"] = pri
	}
	if code != nil {
		changes["ConfirmCodes"] = code
	}
	if groupIds != nil {
		if len(groupIds) == 0 {
			changes["Groups"] = []*authmodel.Group{}
		} else {
			groups, err := m.FindSomeGroup(groupIds, []string{"Id", "Name"})
			if err == nil {
				changes["Groups"] = groups
			}
		}
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

func (m *MgoManager) DeleteUser(id string) error {
	oid, err := getId(id)
	if err != nil {
		return err
	}

	return m.UserColl.RemoveId(oid)
}

func (m *MgoManager) FindUser(id string) (*authmodel.User, error) {
	oid, err := getId(id)
	if err != nil {
		return nil, err
	}

	user := &authmodel.User{}
	err = m.UserColl.FindId(oid).One(user)
	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, authmodel.ErrNotFound
		}

		return nil, err
	}

	return user, nil
}

func (m *MgoManager) FindUserByEmail(email string) (*authmodel.User, error) {
	if !m.Formater.EmailValidate(email) {
		return nil, authmodel.ErrInvalidEmail
	}

	user := &authmodel.User{}
	err := m.UserColl.Find(bson.M{"Email": email}).One(user)
	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, authmodel.ErrNotFound
		}

		return nil, err
	}

	return user, nil
}

func (m *MgoManager) findAll(limit int, offsetId string, fields []string,
	filter bson.M) ([]*authmodel.User, error) {
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

	var users []*authmodel.User
	if limit > 0 {
		query.Limit(limit)
		users = make([]*authmodel.User, 0, limit)
	} else {
		users = []*authmodel.User{}
	}

	err := query.All(&users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (m *MgoManager) FindAllUser(limit int, offsetId string, fields []string,
	groupIds []string) ([]*authmodel.User, error) {
	var filter bson.M
	if groupIds != nil {
		filter = bson.M{"Groups.Id": bson.M{"$in": groupIds}}
	}

	return m.findAll(limit, offsetId, fields, filter)
}

func (m *MgoManager) FindAllUserOnline(limit int, offsetId string, fields []string) (
	[]*authmodel.User, error) {
	return m.findAll(limit, offsetId, fields, bson.M{
		"LastActivity": bson.M{"$lt": time.Now().Add(m.MinimumOnlineThreshold)},
	})
}

func (m *MgoManager) updateLastActivity(id bson.ObjectId) (*authmodel.User, error) {
	user := &authmodel.User{}
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

func (m *MgoManager) GetUser(token string) (*authmodel.User, error) {
	state := LoginState{}
	err := m.LoginColl.FindId(token).One(&state)
	if err != nil {
		if err == mgo.ErrNotFound {
			return nil, authmodel.ErrNotLogged
		}
		return nil, err
	}

	if !state.ExpiredOn.After(time.Now()) {
		m.LoginColl.RemoveId(token)
	}

	return m.updateLastActivity(state.UserId)
}

func (m *MgoManager) Login(id string, stay time.Duration) (string, error) {
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

func (m *MgoManager) Logout(token string) error {
	return m.LoginColl.RemoveId(token)
}

func (m *MgoManager) ComparePassword(ps string, pwd *authmodel.Password) error {
	pwdBytes := []byte(ps)
	tmp := make([]byte, len(pwdBytes)+len(pwd.Salt))
	copy(tmp, pwdBytes)
	tmp = append(tmp, pwd.Salt...)
	if err := bcrypt.CompareHashAndPassword(pwd.Hashed, tmp); err != nil {
		return err
	}

	return nil
}
