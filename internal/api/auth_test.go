package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/h44z/bitwarden-go/internal/database"

	"github.com/go-chi/jwtauth"
	"github.com/h44z/bitwarden-go/internal/common"

	"github.com/DATA-DOG/go-sqlmock"
)

func setup() (*API, sqlmock.Sqlmock) {
	cfg, _ := common.LoadConfiguration("")
	cfg.Database.Type = common.DatabaseTypeMocked
	cfg.Database.Location = "sqlmock_db_0"
	_, mock, _ := sqlmock.NewWithDSN("sqlmock_db_0") // Just create a DSN
	tokenAuth := jwtauth.New("HS256", []byte(cfg.Security.SigningKey), nil)
	db := database.New(cfg)
	db.Open()

	mock.ExpectExec("CREATE TABLE .*").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("CREATE UNIQUE INDEX .*").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("CREATE TABLE .*").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("CREATE TABLE .*").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("CREATE TABLE .*").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("CREATE TABLE .*").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("CREATE TABLE .*").WillReturnResult(sqlmock.NewResult(0, 1))
	db.Initialize()

	api := New(db, cfg, tokenAuth)

	return &api, mock
}

func TestAuthToken(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, _ := http.NewRequest("POST", "/identity/connect/token", strings.NewReader(
		"grant_type=password"+
			"&username=christoph@from.tirol"+
			"&password=geilerhash"+
			"&scope=api offline_access"+
			"&client_id=browser"+
			"&deviceType=3"+
			"&deviceIdentifier=sample-device"+
			"&deviceName=firefox"+
			"&clientName=Cozy"+
			"&devicePushToken="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	// Setup the API
	api, _ := setup()

	// Prepare DB

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.AuthToken)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check Database
	//mock.ExpectBegin()
	/*mock.ExpectBegin()
	mock.ExpectExec("UPDATE products").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO product_viewers").WithArgs(2, 3).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()*/

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the content type of the response
	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("content type header does not match: got %v want %v",
			ctype, "application/json")
	}

	// Check the response body is what we expect.
	expected := `{"alive": true}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}
