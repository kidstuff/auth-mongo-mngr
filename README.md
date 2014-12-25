auth-mongo-mngr
===============

Package implement a [kidstuff/auth manager](https://github.com/kidstuff/auth/wiki/Getting-started) with MongoDB.  

### Install

`
go get github.com/kidstuff/auth-mongo-mngr
`

### Setup
This manager require developer to build some indexes by calling [mgoauth.Setup](http://godoc.org/github.com/kidstuff/auth-mongo-mngr#Setup) in a setup script or by running these command in mongodb shell:    
```javascript
db.mgoauth_user.ensureIndex( { Email: 1 }, { unique: true } )
db.mgoauth_user.ensureIndex( { LastActivity: 1 } )
db.mgoauth_user.ensureIndex( { Groups.Id: 1 } )
db.mgoauth_login.ensureIndex( { UserId: 1 } )
db.mgoauth_login.ensureIndex( { ExpiredOn: 1 }, { expireAfterSeconds: 60 } )
db.mgoauth_group.ensureIndex( { Name: 1 }, { unique: true } )
````

### Usage

```go
import (
	"github.com/kidstuff/auth-mongo-mngr"
	"labix.org/v2/mgo"
)

func main() {
	// connect to database
	session, err := mgo.Dial(MONGODB_URL)
	if err != nil {
		panic(err)
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)
	db := session.DB(DB_NAME)

	// config kidstuff/auth API to work with auth-mongo-mngr
	mgoauth.Initial(db)
}
```