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
			fn: fn,
			cond: auth.Condition{
				RequiredPri: pri,
				Owner:       owner,
			},
		}
	}
}

type mongoMngrHandler struct {
	db   *mgo.Database
	fn   auth.HandleFunc
	cond auth.Condition
}

func (h mongoMngrHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cloneDB := h.db.Session.Clone().DB(h.db.Name)
	defer cloneDB.Session.Close()

	ctx := auth.AuthContext{}
	ctx.Auth = NewMgoManager(cloneDB)
	ctx.Settings = NewMgoConfigMngr(cloneDB)
	auth.BasicMngrHandler(&ctx, rw, req, &h.cond, h.fn)
}
