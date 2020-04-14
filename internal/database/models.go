package database

import (
	"time"
)

type User struct {
	Id                              uint64 `gorm:"primary_key"`
	Name                            string `gorm:"type:varchar(50)"`
	Email                           string `gorm:"type:varchar(50);unique_index;not null"`
	EmailVerified                   bool   `gorm:"not null"`
	MasterPassword                  string `gorm:"type:varchar(300)"`
	MasterPasswordHint              string `gorm:"type:varchar(50)"`
	Culture                         string `gorm:"type:varchar(10);not null"`
	SecurityStamp                   string `gorm:"type:varchar(50);not null"`
	TwoFactorProviders              string `gorm:"type:varchar(65000)"` // JSON
	TwoFactorRecoveryCode           string `gorm:"type:varchar(32)"`
	EquivalentDomains               string
	ExcludedGlobalEquivalentDomains string
	AccountRevisionDate             *time.Time

	Key        string `gorm:"type:varchar(65000)"`
	PublicKey  string `gorm:"type:varchar(65000)"`
	PrivateKey string `gorm:"type:varchar(65000)"`

	Premium               bool `gorm:"not null"`
	PremiumExpirationDate *time.Time
	Storage               int64
	MaxStorageGb          int
	Gateway               int
	GatewayCustomerId     string `gorm:"type:varchar(50)"`
	GatewaySubscriptionId string `gorm:"type:varchar(50)"`
	LicenseKey            string `gorm:"type:varchar(100)"`

	CreationDate        time.Time
	RevisionDate        time.Time
	RenewalReminderDate *time.Time

	Kdf           int
	KdfIterations int

	Folders []Folder
	Ciphers []Cipher
}

type Folder struct {
	Id     uint64 `gorm:"primary_key"`
	UserId uint64
	User   User   `gorm:"foreignkey:UserId"` // Belongs to
	Name   string `gorm:"type:varchar(255)"`

	CreationDate time.Time
	RevisionDate time.Time
}

type Cipher struct {
	Id     uint64 `gorm:"primary_key"`
	UserId uint64
	User   User `gorm:"foreignkey:UserId"` // Belongs to
	//OrganizationId uint64
	//Organization Organization
	Type        int
	Data        string `gorm:"type:varchar(65000)"` // JSON
	Favorites   string `gorm:"type:varchar(65000)"` // JSON
	Folders     string `gorm:"type:varchar(65000)"` // JSON
	Attachments string `gorm:"type:varchar(65000)"` // JSON

	CreationDate time.Time
	RevisionDate time.Time
}

type Device struct {
	Id         uint64 `gorm:"primary_key"`
	UserId     uint64
	User       User   `gorm:"foreignkey:UserId"` // Belongs to
	Name       string `gorm:"type:varchar(50)"`
	Type       int
	Identifier string `gorm:"type:varchar(50)"`
	PushToken  string `gorm:"type:varchar(255)"`

	CreationDate time.Time
	RevisionDate time.Time
}

type U2f struct {
	Id        uint64 `gorm:"primary_key"`
	UserId    uint64
	User      User   `gorm:"foreignkey:UserId"` // Belongs to
	KeyHandle string `gorm:"type:varchar(200)"`
	Challenge string `gorm:"type:varchar(200)"`
	AppId     string `gorm:"type:varchar(50)"`
	Version   string `gorm:"type:varchar(20)"`

	CreationDate time.Time
}

type Grant struct {
	Key       string `gorm:"type:varchar(200);primary_key"`
	Type      string `gorm:"type:varchar(50)"`
	SubjectId string `gorm:"type:varchar(50)"`
	ClientId  string `gorm:"type:varchar(200)"`
	Data      string `gorm:"type:varchar(65000)"`

	CreationDate   time.Time
	ExpirationDate time.Time
}

func (g *Grant) IsExpired() bool {
	return g.ExpirationDate.Before(time.Now())
}
