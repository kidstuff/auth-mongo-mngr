package mgoauth

import (
	"github.com/kidstuff/auth"
	"labix.org/v2/mgo"
	"net/http"
)

func Initial(db *mgo.Database) {
	auth.HandlerRegister = func(fn auth.HandleFunc, owner bool, groups, pri []string) http.Handler {
		return &mongoMngrHandler{
			db: db,
			BasicMngrHandler: auth.BasicMngrHandler{
				Fn:             fn,
				RequiredGroups: groups,
				RequiredPri:    pri,
				Owner:          owner,
			},
		}
	}

	auth.EqualIdChecker = EqualIdChecker
}

type mongoMngrHandler struct {
	db *mgo.Database
	auth.BasicMngrHandler
}

func (h *mongoMngrHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cloneDB := h.db.Session.Clone().DB(h.db.Name)
	defer cloneDB.Session.Close()

	h.AuthContext.Groups = NewMgoGroupManager(cloneDB)
	h.AuthContext.Users = NewMgoUserManager(cloneDB, h.AuthContext.Groups)
	h.AuthContext.Settings = NewMgoConfigMngr(cloneDB)
	h.BasicMngrHandler.ServeHTTP(rw, req)
}
