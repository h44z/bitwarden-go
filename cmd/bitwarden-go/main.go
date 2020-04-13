package main

import (
	"flag"
	"net/http"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/h44z/bitwarden-go/internal/database/mock"

	"github.com/h44z/bitwarden-go/internal/database"
	"github.com/h44z/bitwarden-go/internal/database/sqlite"

	"github.com/h44z/bitwarden-go/internal/api"
	"github.com/h44z/bitwarden-go/internal/auth"
	"github.com/h44z/bitwarden-go/internal/common"
)

func main() {
	common.SetupLogging()

	// Parse input flags
	configFile := flag.String("config", "", "Configuration file.")
	cmdInitDB := flag.Bool("init", false, "Initializes the database.")
	flag.Parse()

	cfg, err := common.LoadConfiguration(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	// Select database implementation
	var db database.Implementation
	switch cfg.Database.Type {
	case common.DatabaseTypeMocked:
		db = &mock.DB{}
	case common.DatabaseTypeSQLite:
		db = &sqlite.DB{}
	case common.DatabaseTypeMySQL:
		log.Error("unimplemented")
		os.Exit(101)
	default:
		log.Errorf("No such database backend %s", cfg.Database.Type)
		os.Exit(102)
	}

	// Open database connection
	err = db.Open(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Re-create database structure
	if *cmdInitDB {
		err := db.Initialize(cfg)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Setup HTTP handlers
	authHandler := auth.New(db, cfg.Security.SigningKey, cfg.Security.JWTExpire)
	apiHandler := api.New(db)

	mux := http.NewServeMux()

	if cfg.Core.DisableRegistration == false {
		mux.HandleFunc("/api/accounts/register", authHandler.HandleRegister)
	}
	mux.HandleFunc("/identity/connect/token", authHandler.HandleLogin)
	mux.HandleFunc("/api/accounts/prelogin", authHandler.HandlePrelogin)

	mux.Handle("/api/accounts/keys", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleKeysUpdate)))
	mux.Handle("/api/accounts/profile", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleProfile)))
	mux.Handle("/api/collections", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleCollections)))
	mux.Handle("/api/folders", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleFolder)))
	mux.Handle("/api/folders/", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleFolderUpdate)))
	mux.Handle("/apifolders", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleFolder))) // The android app want's the address like this, will be fixed in the next version. Issue #174
	mux.Handle("/api/sync", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleSync)))

	mux.Handle("/api/ciphers/import", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleImport)))
	mux.Handle("/api/ciphers", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleCipher)))
	mux.Handle("/api/ciphers/", authHandler.JwtMiddleware(http.HandlerFunc(apiHandler.HandleCipherUpdate)))

	if len(cfg.Core.VaultURL) > 4 {
		proxy := common.Proxy{VaultURL: cfg.Core.VaultURL}
		mux.Handle("/", http.HandlerFunc(proxy.Handler))
	}

	mux.Handle("/api/two-factor/get-authenticator", authHandler.JwtMiddleware(http.HandlerFunc(authHandler.GetAuthenticator)))
	mux.Handle("/api/two-factor/authenticator", authHandler.JwtMiddleware(http.HandlerFunc(authHandler.VerifyAuthenticatorSecret)))
	mux.Handle("/api/two-factor/disable", authHandler.JwtMiddleware(http.HandlerFunc(authHandler.HandleDisableTwoFactor)))
	mux.Handle("/api/two-factor", authHandler.JwtMiddleware(http.HandlerFunc(authHandler.HandleTwoFactor)))

	// Startup HTTP server
	log.Infof("Starting server on %s:%d", cfg.Core.ListenAddress, cfg.Core.Port)
	log.Fatal(http.ListenAndServe(cfg.Core.ListenAddress+":"+strconv.Itoa(cfg.Core.Port), mux))
}
