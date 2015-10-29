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

type XormAuth struct {
	allowAnony  bool
	defaultPerm os.FileMode
	orm         *xorm.Engine
	encryptFunc func(string) string
}

func (auth *XormAuth) CheckPasswd(userName, pass string) bool {
	if auth.allowAnony && userName == "anonymous" {
		return true
	}

	var user = User{Name: userName}
	has, err := auth.orm.Get(&user)
	if err != nil {
		log.Error(err)
		return false
	}
	if !has {
		return false
	}

	return user.Pass == auth.encryptFunc(pass)
}

func NoEncrypt(s string) string {
	return s
}

func NewXormAuth(orm *xorm.Engine, allowAnony bool, perm os.FileMode, encryptFunc func(string) string) (*XormAuth, error) {
	err := orm.Sync2(new(User))
	if err != nil {
		return nil, err
	}

	return &XormAuth{allowAnony, os.ModePerm, orm, encryptFunc}, nil
}
