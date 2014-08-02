package xormauth

import (
	"time"

	"github.com/go-xorm/xorm"
	"github.com/go-xweb/log"
	"github.com/goftp/server"
)

type User struct {
	Id      int64
	Name    string `xorm:"unique"`
	Pass    string
	Created time.Time `xorm:"created"`
}

type Perm struct {
	Id       int64
	UserName string
	Path     string
	Perm     int
	Created  time.Time `xorm:"created"`
}

type XormAuth struct {
	allowAnony  bool
	defaultPerm int
	orm         *xorm.Engine
}

func (auth *XormAuth) AllowAnonymous(allow bool) {
	auth.allowAnony = allow
}

func (auth *XormAuth) DefaultPerm(perm int) {
	auth.defaultPerm = perm
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

func (auth *XormAuth) GetPerms(user, path string) int {
	perm := &Perm{UserName: user, Path: path}
	has, err := auth.orm.Get(perm)
	if err != nil {
		log.Error(err)
		return 0
	}
	if !has {
		return auth.defaultPerm
	}
	return perm.Perm
}

func NewXormAuth(orm *xorm.Engine) (*XormAuth, error) {
	err := orm.Sync(new(User), new(Perm))
	if err != nil {
		return nil, err
	}

	return &XormAuth{false, server.Read + server.Write, orm}, nil
}
