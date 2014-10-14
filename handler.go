package mgoauth

import (
	"github.com/kidstuff/auth"
	"labix.org/v2/mgo"
	"net/http"
)

func Initial(db *mgo.Database) {
	auth.HANDLER_REGISTER = func(fn auth.HandleFunc, owner bool, groups, pri []string) http.Handler {
		return mongoMngrHandler{
			db: db,
			Fn: fn,
			Condition: auth.Condition{
				RequiredGroups: groups,
				RequiredPri:    pri,
				Owner:          owner,
			},
		}
	}
}

type mongoMngrHandler struct {
	db *mgo.Database
	Fn auth.HandleFunc
	auth.Condition
	auth.AuthContext
}

func (h mongoMngrHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cloneDB := h.db.Session.Clone().DB(h.db.Name)
	defer cloneDB.Session.Close()

	h.AuthContext.Groups = NewMgoGroupManager(cloneDB)
	h.AuthContext.Users = NewMgoUserManager(cloneDB, h.AuthContext.Groups)
	h.AuthContext.Settings = NewMgoConfigMngr(cloneDB)
	auth.BasicMngrHandler(&h.AuthContext, rw, req, &h.Condition, h.Fn)
}
