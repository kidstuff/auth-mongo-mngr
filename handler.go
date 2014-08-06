package mgoauth

import (
	"github.com/kidstuff/auth"
	"github.com/kidstuff/auth/model"
	"labix.org/v2/mgo"
	"log"
	"net/http"
	"strings"
)

func Initial(db *mgo.Database) {
	auth.HandlerRegister = func(fn auth.HandleFunc, groups []string, pri []string) http.Handler {
		return &mongoMngrHandler{
			db:             db,
			fn:             fn,
			requiredGroups: groups,
			requiredPri:    pri,
		}
	}
}

type mongoMngrHandler struct {
	db *mgo.Database
	auth.AuthContext
	fn             auth.HandleFunc
	requiredGroups []string
	requiredPri    []string
}

func (h *mongoMngrHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	cloneDB := h.db.Session.Clone().DB(h.db.Name)
	defer cloneDB.Session.Close()

	h.AuthContext.Groups = NewMgoGroupManager(cloneDB)
	h.AuthContext.Users = NewMgoUserManager(cloneDB, h.AuthContext.Groups)

	if h.requiredGroups != nil || h.requiredPri != nil {
		token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		user, err := h.CurrentUser(token)
		if err != nil {
			if err == model.ErrNotLogged {
				jsonError(rw, err.Error(), http.StatusForbidden)
				return
			}

			jsonError(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		// check if any groups of the current user match one of the required groups
		if len(h.requiredGroups) > 0 {
			for _, bg := range user.BriefGroups {
				for _, g2 := range h.requiredGroups {
					if *bg.Name == g2 {
						goto NORMAL
					}
				}
			}
		}

		// check if any privileges of the current user match one of the required privileges
		if len(h.requiredPri) > 0 {
			for _, pri := range user.Privilege {
				for _, p := range h.requiredPri {
					if pri == p {
						goto NORMAL
					}
				}
			}
		}

		// check if any groups of the current user has the privileges match one of required privileges
		aid := make([]interface{}, 0, len(user.BriefGroups))
		for _, v := range user.BriefGroups {
			aid = append(aid, v.Id)
		}

		groups, err := h.AuthContext.Groups.FindSome(aid...)
		if err != nil {
			jsonError(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		for _, v := range groups {
			for _, pri := range v.Privilege {
				for _, p := range h.requiredPri {
					if pri == p {
						goto NORMAL
					}
				}
			}
		}

		jsonError(rw, err.Error(), http.StatusForbidden)
		return
	}

NORMAL:
	status, err := h.fn(&h.AuthContext, rw, req)
	if err != nil {
		log.Printf("HTTP %d: %q", status, err)
		jsonError(rw, err.Error(), status)
	}
}

func jsonError(rw http.ResponseWriter, message string, code int) {
	rw.WriteHeader(code)
	rw.Write([]byte(`{"error":"` + message + `"}`))
}
