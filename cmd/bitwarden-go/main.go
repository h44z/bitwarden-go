package main

import (
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/jwtauth"

	log "github.com/sirupsen/logrus"

	"github.com/h44z/bitwarden-go/internal/api"
	"github.com/h44z/bitwarden-go/internal/common"
	"github.com/h44z/bitwarden-go/internal/database"
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

	// Open database connection
	db := database.New(cfg)
	err = db.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Re-create database structure
	if *cmdInitDB {
		err := db.Initialize()
		if err != nil {
			log.Fatal(err)
		}
	}

	// Setup HTTP handlers
	tokenAuth := jwtauth.New("HS256", []byte(cfg.Security.SigningKey), nil)
	apiHandler := api.New(db, cfg, tokenAuth)
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	})

	router := chi.NewRouter()

	// A good base middleware stack
	router.Use(corsMiddleware.Handler)
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	router.Use(middleware.Timeout(180 * time.Second))

	// Public routes
	router.Group(func(r chi.Router) {
		if cfg.Core.DisableRegistration == false {
			r.Post("/api/accounts/register", apiHandler.AccountRegister)
		}
		r.Post("/api/accounts/prelogin", apiHandler.AccountPrelogin)
		r.Post("/identity/connect/token", apiHandler.AuthToken)
	})

	// Protected routes
	router.Group(func(r chi.Router) {
		// Seek, verify and validate JWT tokens
		r.Use(jwtauth.Verifier(tokenAuth))

		// Handle valid / invalid tokens. In this example, we use
		// the provided authenticator middleware, but you can write your
		// own very easily, look at the Authenticator method in jwtauth.go
		// and tweak it, its not scary.
		r.Use(jwtauth.Authenticator)

		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			_, claims, _ := jwtauth.FromContext(r.Context())
			w.Write([]byte(fmt.Sprintf("protected area. hi %v", claims["user_id"])))
		})
	})

	/*
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
	*/

	// Startup HTTP server
	log.Infof("Starting server on %s:%d", cfg.Core.ListenAddress, cfg.Core.Port)
	log.Fatal(http.ListenAndServe(cfg.Core.ListenAddress+":"+strconv.Itoa(cfg.Core.Port), router))
}
