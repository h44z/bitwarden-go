package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	bw "github.com/h44z/bitwarden-go/internal/common"
	"github.com/h44z/bitwarden-go/internal/database"
)

// AccountPrelogin allows the client to know the number of KDF iterations to apply when hashing the master password.
func (a *API) AccountPrelogin(w http.ResponseWriter, req *http.Request) {
	var requestData struct {
		email string
	}

	// Get email
	err := json.NewDecoder(req.Body).Decode(&requestData)
	if err != nil {
		log.Errorf("prelogin decoding failed: %s", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get account data from DB
	var user database.User
	ok := a.db.DB.First(&user, "email = ?", requestData.email).RecordNotFound()
	if !ok {
		// Use some fallback values, do not leak information about a non existent user.
		user.Kdf = 0
		user.KdfIterations = 100000
	}

	// Return Kdf data
	userKdfInformation := struct {
		Kdf           int
		KdfIterations int
	}{
		Kdf:           user.Kdf,
		KdfIterations: user.KdfIterations,
	}

	MustRespondJSON(w, &userKdfInformation)
}

// AccountRegister allows user registration.
func (a *API) AccountRegister(w http.ResponseWriter, req *http.Request) {
	var requestData bw.RegisterModel

	err := json.NewDecoder(req.Body).Decode(&requestData)
	if err != nil {
		log.Errorf("register decoding failed: %s", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Infof(requestData.Email + " is trying to register")

	// Check iterations
	if requestData.KdfIterations < 5000 || requestData.KdfIterations > 100000 {
		http.Error(w, "unsupported iteration count", http.StatusBadRequest)
		return
	}

	// Create user in database
	user, err := a.db.CreateUserFromRegistrationModel(&requestData)
	if err != nil {
		log.Errorf("registering user failed: %s", err.Error())
		time.Sleep(2 * time.Second) // delay response to avoid denial of service attacks
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Send welcome email
	err = bw.SendEmail(a.cfg, "Bitwarden account created",
		strings.Replace(bw.EmailWelcome, "{WebVaultUrl}", a.cfg.Core.VaultURL, -1), user.Email)
	if err != nil {
		log.Errorf("register email failed: %s", err.Error())
	}
}
