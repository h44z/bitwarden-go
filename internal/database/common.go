package database

import bw "github.com/h44z/bitwarden-go/internal/common"

type Implementation interface {
	Open(cfg *bw.Configuration) error
	Initialize(cfg *bw.Configuration) error
	Close()

	// Extra functions
	AddAccount(acc bw.Account) error
	GetAccount(username string, refreshtoken string) (bw.Account, error)
	UpdateAccountInfo(acc bw.Account) error
	Update2FAsecret(secret string, email string) error
	GetCipher(owner string, ciphID string) (bw.Cipher, error)
	GetCiphers(owner string) ([]bw.Cipher, error)
	NewCipher(ciph bw.Cipher, owner string) (bw.Cipher, error)
	UpdateCipher(newData bw.Cipher, owner string, ciphID string) error
	DeleteCipher(owner string, ciphID string) error
	AddFolder(name string, owner string) (bw.Folder, error)
	UpdateFolder(newFolder bw.Folder, owner string) error
	GetFolders(owner string) ([]bw.Folder, error)
}
