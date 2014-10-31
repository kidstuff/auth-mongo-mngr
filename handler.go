package mgoauth

import (
	"github.com/kidstuff/auth"
	"labix.org/v2/mgo"
	"net/http"
)

// Initial function should be called in the application first start
func Initial(db *mgo.Database) {
	auth.HANDLER_REGISTER = func(fn auth.HandleFunc, owner bool, pri []string) http.Handler {
		return mongoMngrHandler{
			db: db,
			Fn: fn,
			Condition: auth.Condition{
				RequiredPri: pri,
				Owner:       owner,
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

	h.AuthContext.Auth = NewMgoManager(cloneDB)
	h.AuthContext.Settings = NewMgoConfigMngr(cloneDB)
	auth.BasicMngrHandler(&h.AuthContext, rw, req, &h.Condition, h.Fn)
}
