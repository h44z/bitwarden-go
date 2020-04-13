package mock

import (
	bw "github.com/h44z/bitwarden-go/internal/common"
	_ "github.com/mattn/go-sqlite3"
)

// mock database used for testing
type DB struct {
	Username        string
	Password        string
	RefreshToken    string
	TwoFactorSecret string
	KdfIterations   int
}

func (db *DB) UpdateFolder(newFolder bw.Folder, owner string) error {
	return nil
}

func (db *DB) Initialize(cfg *bw.Configuration) error {
	return nil
}

func (db *DB) Open(cfg *bw.Configuration) error {
	return nil
}

func (db *DB) Close() {
}

func (db *DB) UpdateAccountInfo(acc bw.Account) error {
	return nil
}

func (db *DB) GetCipher(owner string, ciphID string) (bw.Cipher, error) {
	return bw.Cipher{}, nil
}

func (db *DB) GetCiphers(owner string) ([]bw.Cipher, error) {
	return nil, nil
}

func (db *DB) NewCipher(ciph bw.Cipher, owner string) (bw.Cipher, error) {
	return bw.Cipher{}, nil

}

func (db *DB) UpdateCipher(newData bw.Cipher, owner string, ciphID string) error {
	return nil
}

func (db *DB) DeleteCipher(owner string, ciphID string) error {
	return nil
}

func (db *DB) AddAccount(acc bw.Account) error {
	return nil
}

func (db *DB) GetAccount(username string, refreshtoken string) (bw.Account, error) {
	return bw.Account{Email: db.Username, MasterPasswordHash: db.Password, RefreshToken: db.RefreshToken, TwoFactorSecret: db.TwoFactorSecret, KdfIterations: db.KdfIterations}, nil
}

func (db *DB) AddFolder(name string, owner string) (bw.Folder, error) {
	return bw.Folder{}, nil
}

func (db *DB) GetFolders(owner string) ([]bw.Folder, error) {
	return nil, nil
}

func (db *DB) Update2FAsecret(secret string, email string) error {
	return nil
}
