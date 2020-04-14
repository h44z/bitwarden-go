package database

import (
	bw "github.com/h44z/bitwarden-go/internal/common"
	_ "github.com/mattn/go-sqlite3"
)

// mock database used for testing
type Mock struct {
	Username        string
	Password        string
	RefreshToken    string
	TwoFactorSecret string
	KdfIterations   int
}

func (db *Mock) UpdateFolder(newFolder bw.Folder, owner string) error {
	return nil
}

func (db *Mock) Initialize(cfg *bw.Configuration) error {
	return nil
}

func (db *Mock) Open(cfg *bw.Configuration) error {
	return nil
}

func (db *Mock) Close() {
}

func (db *Mock) UpdateAccountInfo(acc bw.Account) error {
	return nil
}

func (db *Mock) GetCipher(owner string, ciphID string) (bw.Cipher, error) {
	return bw.Cipher{}, nil
}

func (db *Mock) GetCiphers(owner string) ([]bw.Cipher, error) {
	return nil, nil
}

func (db *Mock) NewCipher(ciph bw.Cipher, owner string) (bw.Cipher, error) {
	return bw.Cipher{}, nil

}

func (db *Mock) UpdateCipher(newData bw.Cipher, owner string, ciphID string) error {
	return nil
}

func (db *Mock) DeleteCipher(owner string, ciphID string) error {
	return nil
}

func (db *Mock) AddAccount(acc bw.Account) error {
	return nil
}

func (db *Mock) GetAccount(username string, refreshtoken string) (bw.Account, error) {
	return bw.Account{Email: db.Username, MasterPasswordHash: db.Password, RefreshToken: db.RefreshToken, TwoFactorSecret: db.TwoFactorSecret, KdfIterations: db.KdfIterations}, nil
}

func (db *Mock) AddFolder(name string, owner string) (bw.Folder, error) {
	return bw.Folder{}, nil
}

func (db *Mock) GetFolders(owner string) ([]bw.Folder, error) {
	return nil, nil
}

func (db *Mock) Update2FAsecret(secret string, email string) error {
	return nil
}
