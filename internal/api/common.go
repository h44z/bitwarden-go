package api

import (
	"github.com/go-chi/jwtauth"
	bw "github.com/h44z/bitwarden-go/internal/common"
	"github.com/h44z/bitwarden-go/internal/database"
)

type API struct {
	db  *database.Wrapper
	cfg *bw.Configuration
	jwt *jwtauth.JWTAuth
}

func New(db *database.Wrapper, cfg *bw.Configuration, jwt *jwtauth.JWTAuth) API {
	auth := API{
		db:  db,
		cfg: cfg,
		jwt: jwt,
	}

	return auth
}
