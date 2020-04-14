package database

import (
	"path"

	bw "github.com/h44z/bitwarden-go/internal/common"
	"github.com/jinzhu/gorm"

	_ "github.com/mattn/go-sqlite3" // Driver import
)

type Wrapper struct {
	DB            *gorm.DB
	Configuration *bw.Configuration
}

type Implementation interface {
	Open() error
	Initialize() error
	Close()
}

func New(cfg *bw.Configuration) *Wrapper {
	return &Wrapper{
		Configuration: cfg,
	}
}

func (db *Wrapper) Initialize() error {
	// Migrate the schema
	db.DB.AutoMigrate(&User{}, &Folder{}, &Cipher{}, &Device{}, &U2f{}, &Grant{})
	return nil
}

func (db *Wrapper) Open() error {
	var err error
	// TODO: select correct driver
	switch db.Configuration.Database.Type {
	case bw.DatabaseTypeMocked:
		db.DB, err = gorm.Open("sqlmock", db.Configuration.Database.Location)
	case bw.DatabaseTypeMySQL:
	case bw.DatabaseTypeSQLite:
		if db.Configuration.Database.Location != "" {
			db.DB, err = gorm.Open("sqlite3", path.Join(db.Configuration.Database.Location, "db"))
		} else {
			db.DB, err = gorm.Open("sqlite3", "db")
		}
	}

	return err
}

func (db *Wrapper) Close() {
	_ = db.DB.Close()
}
