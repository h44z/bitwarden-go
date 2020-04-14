package database

import (
	"time"

	"github.com/h44z/bitwarden-go/internal/common"
)

func (db *Wrapper) CreateUserFromRegistrationModel(model *common.RegisterModel) (*User, error) {
	currentTime := time.Now()
	user := &User{
		Name:                            model.Name,
		Email:                           model.Email,
		EmailVerified:                   false,
		MasterPassword:                  model.MasterPasswordHash,
		MasterPasswordHint:              truncateString(model.MasterPasswordHint, 50),
		Culture:                         "en-US",
		SecurityStamp:                   "",
		TwoFactorProviders:              "",
		TwoFactorRecoveryCode:           "",
		EquivalentDomains:               "",
		ExcludedGlobalEquivalentDomains: "",
		AccountRevisionDate:             &currentTime,
		Key:                             model.Key,
		PublicKey:                       model.Keys.PublicKey,
		PrivateKey:                      model.Keys.EncryptedPrivateKey,
		Premium:                         true,
		PremiumExpirationDate:           nil,
		Storage:                         0,
		MaxStorageGb:                    1024,
		Gateway:                         0,
		GatewayCustomerId:               "",
		GatewaySubscriptionId:           "",
		LicenseKey:                      "",
		CreationDate:                    currentTime,
		RevisionDate:                    currentTime,
		RenewalReminderDate:             nil,
		Kdf:                             model.Kdf,
		KdfIterations:                   model.KdfIterations,
		Folders:                         nil,
		Ciphers:                         nil,
	}

	err := db.DB.Create(user).Error

	return user, err
}

func truncateString(str string, num int) string {
	result := str
	if len(str) > num {
		if num > 3 {
			num -= 3
		}
		result = str[0:num] + "..."
	}
	return result
}
