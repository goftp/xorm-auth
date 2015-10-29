package xormauth

import (
	"os"
	"time"

	"github.com/go-xorm/xorm"
	"github.com/go-xweb/log"
)

type User struct {
	Id      int64
	Name    string `xorm:"unique"`
	Pass    string
	Created time.Time `xorm:"created"`
}

type Group struct {
	Id      int64
	Name    string    `xorm:"unique"`
	Created time.Time `xorm:"created"`
}

type UserGroup struct {
	UserName  string `xorm:"pk"`
	GroupName string `xorm:"pk"`
}

type Perm struct {
	Id      int64
	Path    string `xorm:"unique"`
	Owner   string
	Group   string
	Mode    os.FileMode
	Created time.Time `xorm:"created"`
	Updated time.Time `xorm:"updated"`
}

type XormAuth struct {
	allowAnony  bool
	defaultPerm os.FileMode
	orm         *xorm.Engine
}

func (auth *XormAuth) CheckPasswd(user, pass string) bool {
	if auth.allowAnony && user == "anonymous" {
		return true
	}

	has, err := auth.orm.Get(&User{Name: user, Pass: pass})
	if err != nil {
		log.Error(err)
		return false
	}
	return has
}

func NewXormAuth(orm *xorm.Engine) (*XormAuth, error) {
	err := orm.Sync(new(User), new(Perm))
	if err != nil {
		return nil, err
	}

	return &XormAuth{false, os.ModePerm, orm}, nil
}
