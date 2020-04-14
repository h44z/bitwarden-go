package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/h44z/bitwarden-go/internal/common"

	"github.com/h44z/bitwarden-go/internal/database"

	"github.com/dgrijalva/jwt-go"

	log "github.com/sirupsen/logrus"
)

func (a *API) AuthToken(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	err := validateLoginFields(req)
	if err != nil {
		log.Errorf("Login failed, pre-check failed: %s", err.Error())
		time.Sleep(2 * time.Second) // delay response to avoid denial of service attacks
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	grantType := req.PostForm["grant_type"][0]
	clientID := req.PostForm["client_id"][0]
	scope := req.PostForm["scope"][0]

	var user database.User
	var grant database.Grant
	if grantType == "refresh_token" {
		refreshToken := req.PostForm["refresh_token"][0]
		ok := a.db.DB.First(&grant, refreshToken).RecordNotFound()
		if !ok {
			log.Error("Login failed, invalid refresh token")
			time.Sleep(2 * time.Second) // delay response to avoid denial of service attacks
			http.Error(w, "invalid refresh_token", http.StatusUnauthorized)
			return
		}

		userID, _ := strconv.Atoi(grant.SubjectId)
		ok = a.db.DB.Where("Id = ?", userID).First(&user).RecordNotFound()
		if !ok {
			log.Errorf("Login failed, refresh token not linked to any user %s, %s", grant.Key, grant.SubjectId)
			http.Error(w, "invalid refresh_token", http.StatusUnauthorized)
			return
		}
		if grant.IsExpired() {
			log.Errorf("Login failed, refresh token expired %s, %s", grant.Key, grant.SubjectId)
			a.db.DB.Delete(&grant) // remove expired grant
			http.Error(w, "expired refresh_token", http.StatusUnauthorized)
			return
		}

		log.Infof("User %s is trying to refresh the access token for %s", user.Email, grant.ClientId)
	} else if grantType == "password" {
		username := req.PostForm["username"][0]
		passwordHash := req.PostForm["password"][0]

		fail := a.db.DB.Where("email = ?", username).First(&user).RecordNotFound()
		if fail {
			log.Errorf("Login failed, user not found: %s", username)
			time.Sleep(2 * time.Second) // delay response to avoid denial of service attacks
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		log.Infof("User %s is trying to login", username)

		if err := validateCredentials(&user, passwordHash); err != nil {
			log.Errorf("Login failed, invalid credentials: %s", username)
			time.Sleep(2 * time.Second) // delay response to avoid denial of service attacks
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// TODO: 2fa
	}

	if user.Email == "" {
		log.Error("login, user email empty?!")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	log.Infof("User %s authenticated, creating token", user.Email)

	claims := jwt.MapClaims{}
	claims["client_id"] = clientID
	claims["scope"] = scope
	claims["nbf"] = time.Now().Unix()
	claims["iat"] = time.Now().Unix()
	claims["auth_time"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Second * time.Duration(a.cfg.Security.JWTExpire)).Unix()
	claims["iss"] = "bitwarden-go"
	claims["sub"] = user.Id
	claims["email"] = user.Email
	claims["name"] = user.Name
	claims["premium"] = user.Premium
	claims["email_verified"] = user.EmailVerified
	claims["sstamp"] = user.SecurityStamp
	claims["device"] = req.PostForm["deviceIdentifier"][0]

	_, tokenString, err := a.jwt.Encode(claims)

	// Check if a valid refresh token exists, if not, create a new one
	grant = database.Grant{}
	if grantType == "password" {
		refreshToken := make([]byte, 32)
		if _, err := rand.Read(refreshToken); err != nil {
			log.Errorf("login, failed to read rand: %s", err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		grant.Key = base64.StdEncoding.EncodeToString(refreshToken)
		grant.CreationDate = time.Now()
		grant.ExpirationDate = time.Now().Add(time.Hour * 168) // 1 week
		grant.ClientId = clientID
		grant.SubjectId = strconv.FormatUint(user.Id, 10)
		grant.Type = "refresh_token"
		if claimsJSON, err := json.Marshal(claims); err == nil {
			grant.Data = string(claimsJSON)
		}

		if err := a.db.DB.Create(&grant).Error; err != nil {
			log.Errorf("login, failed to create refresh token: %s", err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}

	tokenModel := common.TokenModel{
		ClientId:     clientID,
		AccessToken:  tokenString,
		ExpiresIn:    a.cfg.Security.JWTExpire,
		TokenType:    "Bearer",
		RefreshToken: grant.Key,
		Key:          user.Key,
	}
	if clientID == "web" {
		tokenModel.PrivateKey = user.PrivateKey
	}

	if jsonToken, err := json.Marshal(&tokenModel); err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonToken)
	} else {
		log.Errorf("login, failed to marshal token: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// validateLoginFields checks if all required fields are set in the login request.
func validateLoginFields(req *http.Request) error {
	grantType, ok := req.PostForm["grant_type"]
	if !ok {
		return errors.New("grant_type is missing")
	}
	if grantType[0] != "refresh_token" && grantType[0] != "password" {
		return errors.New("unsupported grant_type")
	}

	_, ok = req.PostForm["client_id"]
	if !ok {
		return errors.New("client_id is missing")
	}

	_, ok = req.PostForm["scope"]
	if !ok {
		return errors.New("scope is missing")
	}

	_, ok = req.PostForm["deviceIdentifier"]
	if !ok {
		return errors.New("deviceIdentifier is missing")
	}

	_, ok = req.PostForm["deviceType"]
	if !ok {
		return errors.New("deviceType is missing")
	}

	_, ok = req.PostForm["deviceName"]
	if !ok {
		return errors.New("deviceName is missing")
	}

	_, okRefresh := req.PostForm["refresh_token"]
	_, okUsername := req.PostForm["username"]
	_, okPassword := req.PostForm["password"]
	if !okRefresh && grantType[0] == "refresh_token" {
		return errors.New("refresh_token is missing")
	}
	if (!okUsername || !okPassword) && grantType[0] == "password" {
		return errors.New("username or password is missing")
	}

	return nil
}

// validateCredentials checks if the password matches the user record.
func validateCredentials(user *database.User, password string) error {
	if password == "" {
		return errors.New("invalid credentials")
	}
	if user.MasterPassword != password {
		return errors.New("invalid credentials")
	}

	return nil
}
