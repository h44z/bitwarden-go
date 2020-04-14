package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jinzhu/gorm"

	"github.com/h44z/bitwarden-go/internal/database"

	"github.com/go-chi/jwtauth"
	"github.com/h44z/bitwarden-go/internal/common"
)

func setup(t *testing.T) *API {
	cfg, _ := common.LoadConfiguration("")
	cfg.Database.Type = common.DatabaseTypeSQLite
	cfg.Database.Location = "__test_db.sqlite"
	tokenAuth := jwtauth.New("HS256", []byte(cfg.Security.SigningKey), nil)
	db := database.New(cfg)
	db.Open()
	db.Initialize()

	api := New(db, cfg, tokenAuth)

	t.Cleanup(func() {
		db.Close()
		os.Remove(cfg.Database.Location)
	})

	return &api
}

func createUser(t *testing.T, db *gorm.DB) {
	user := database.User{
		Name:               "Tester",
		Email:              "test@test.com",
		EmailVerified:      true,
		MasterPassword:     "notarealhash",
		MasterPasswordHint: "well...",
		Culture:            "en-US",
		SecurityStamp:      "hmmm",
		Key:                "supersecretkey",
		PublicKey:          "thepublickey",
		PrivateKey:         "aprivatekey",
		CreationDate:       time.Now(),
		RevisionDate:       time.Now(),
		Kdf:                0,
		KdfIterations:      6000,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		db.Delete(&user)
	})
}

func deleteRefreshTokens(t *testing.T, db *gorm.DB) {
	if err := db.Unscoped().Delete(&database.Grant{}).Error; err != nil {
		t.Fatal(err)
	}
}

func TestInvalidCredentials(t *testing.T) {
	// Setup the API
	api := setup(t)

	// Prepare DB
	createUser(t, api.db.DB)

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, _ := http.NewRequest("POST", "/identity/connect/token", strings.NewReader(
		"grant_type=password"+
			"&username=test@test.com"+
			"&password=notcorrect"+
			"&scope=api offline_access"+
			"&client_id=browser"+
			"&deviceType=3"+
			"&deviceIdentifier=sample-device"+
			"&deviceName=firefox"+
			"&clientName=Cozy"+
			"&devicePushToken="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.AuthToken)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}

	// Check the content type of the response
	if ctype := rr.Header().Get("Content-Type"); !strings.HasPrefix(ctype, "text/plain") {
		t.Errorf("content type header does not match: got %v want %v",
			ctype, "text/plain")
	}

	// Check the response body is what we expect.
	if strings.TrimSpace(rr.Body.String()) != "Unauthorized" {
		t.Errorf("handler returned unexpected body: got %v want %v",
			strings.TrimSpace(rr.Body.String()), "Unauthorized")
	}
}

func TestInvalidRequest(t *testing.T) {
	// Setup the API
	api := setup(t)

	// Prepare DB
	createUser(t, api.db.DB)

	// Skip grant type
	req, _ := http.NewRequest("POST", "/identity/connect/token", strings.NewReader(
		"username=test@test.com"+
			"&password=notcorrect"+
			"&scope=api offline_access"+
			"&client_id=browser"+
			"&deviceType=3"+
			"&deviceName=firefox"+
			"&deviceIdentifier=sample-device"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.AuthToken)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}

	if strings.TrimSpace(rr.Body.String()) != "grant_type is missing" {
		t.Errorf("handler returned unexpected body: got %v want %v",
			strings.TrimSpace(rr.Body.String()), "grant_type is missing")
	}

	// Unsupported grant_type
	req, _ = http.NewRequest("POST", "/identity/connect/token", strings.NewReader(
		"grant_type=gimmeaccess"+
			"&username=test@test.com"+
			"&password=notcorrect"+
			"&scope=api offline_access"+
			"&client_id=browser"+
			"&deviceType=3"+
			"&deviceName=firefox"+
			"&deviceIdentifier=sample-device"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}

	if strings.TrimSpace(rr.Body.String()) != "unsupported grant_type" {
		t.Errorf("handler returned unexpected body: got %v want %v",
			strings.TrimSpace(rr.Body.String()), "unsupported grant_type")
	}

	// Missing username
	req, _ = http.NewRequest("POST", "/identity/connect/token", strings.NewReader(
		"grant_type=password"+
			"&password=notcorrect"+
			"&scope=api offline_access"+
			"&client_id=browser"+
			"&deviceType=3"+
			"&deviceName=firefox"+
			"&deviceIdentifier=sample-device"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}

	if strings.TrimSpace(rr.Body.String()) != "username or password is missing" {
		t.Errorf("handler returned unexpected body: got %v want %v",
			strings.TrimSpace(rr.Body.String()), "username or password is missing")
	}
}

func TestEmptyPassword(t *testing.T) {
	// Setup the API
	api := setup(t)

	// Prepare DB
	createUser(t, api.db.DB)

	// Empty password
	req, _ := http.NewRequest("POST", "/identity/connect/token", strings.NewReader(
		"grant_type=password"+
			"&username=test@test.com"+
			"&password="+
			"&scope=api offline_access"+
			"&client_id=browser"+
			"&deviceType=3"+
			"&deviceName=firefox"+
			"&deviceIdentifier=sample-device"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.AuthToken)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}

	if strings.TrimSpace(rr.Body.String()) != "Unauthorized" {
		t.Errorf("handler returned unexpected body: got %v want %v",
			strings.TrimSpace(rr.Body.String()), "Unauthorized")
	}
}

func TestPasswordLogin(t *testing.T) {
	// Setup the API
	api := setup(t)

	// Prepare DB
	createUser(t, api.db.DB)

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, _ := http.NewRequest("POST", "/identity/connect/token", strings.NewReader(
		"grant_type=password"+
			"&username=test@test.com"+
			"&password=notarealhash"+
			"&scope=api offline_access"+
			"&client_id=browser"+
			"&deviceType=3"+
			"&deviceIdentifier=sample-device"+
			"&deviceName=firefox"+
			"&clientName=Cozy"+
			"&devicePushToken="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.AuthToken)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the content type of the response
	if ctype := rr.Header().Get("Content-Type"); !strings.HasPrefix(ctype, "application/json") {
		t.Errorf("content type header does not match: got %v want %v",
			ctype, "application/json")
	}

	// Check the response body is what we expect.
	if body := rr.Body.String(); !strings.Contains(body, "access_token") || !strings.Contains(body, "\"client_id\":\"browser\"") {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), "{\"client_id\":\"browser\",\"access_token\" ...")
	}
}

func TestRefreshToken(t *testing.T) {
	// Setup the API
	api := setup(t)

	// Prepare DB
	createUser(t, api.db.DB)
	deleteRefreshTokens(t, api.db.DB)

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, _ := http.NewRequest("POST", "/identity/connect/token", strings.NewReader(
		"grant_type=password"+
			"&username=test@test.com"+
			"&password=notarealhash"+
			"&scope=api offline_access"+
			"&client_id=browser"+
			"&deviceType=3"+
			"&deviceIdentifier=sample-device"+
			"&deviceName=firefox"+
			"&clientName=Cozy"+
			"&devicePushToken="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.AuthToken)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the content type of the response
	if ctype := rr.Header().Get("Content-Type"); !strings.HasPrefix(ctype, "application/json") {
		t.Errorf("content type header does not match: got %v want %v",
			ctype, "application/json")
	}

	// Check the response body is what we expect.
	var jsonResponse struct {
		ClientID     string `json:"client_id"`
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		Key          string `json:"Key"`
	}
	if body := rr.Body.String(); !strings.Contains(body, "refresh_token") {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), "{\"refresh_token\" ...")
	} else {
		json.Unmarshal([]byte(body), &jsonResponse)
	}
	if jsonResponse.RefreshToken == "" {
		t.Errorf("unable to extract refresh token")
	}

	// Login via refresh token
	req, _ = http.NewRequest("POST", "/identity/connect/token", strings.NewReader(
		"grant_type=refresh_token"+
			"&refresh_token="+url.QueryEscape(jsonResponse.RefreshToken)+
			"&scope=api offline_access"+
			"&client_id=browser"+
			"&deviceType=3"+
			"&deviceName=firefox"+
			"&deviceIdentifier=sample-device"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	if ctype := rr.Header().Get("Content-Type"); !strings.HasPrefix(ctype, "application/json") {
		t.Errorf("content type header does not match: got %v want %v",
			ctype, "application/json")
	}

	if body := rr.Body.String(); !strings.Contains(body, "access_token") || !strings.Contains(body, "\"client_id\":\"browser\"") {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), "{\"client_id\":\"browser\",\"access_token\" ...")
	}
}
