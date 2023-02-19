package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
)

func TestHandleLogin(t *testing.T) {
	// Create a new request with a JSON request body
	reqBody := strings.NewReader(`{"username":"testuser","password":"testpassword"}`)
	req, err := http.NewRequest("POST", "/login", reqBody)
	if err != nil {
		t.Fatal(err)
	}
	// Set the content type to JSON
	req.Header.Set("Content-Type", "application/json")

	// Create a new ResponseRecorder (which satisfies http.ResponseWriter) to capture the response
	rr := httptest.NewRecorder()

	// Create a mock DB connection to pass to the handler
	db, err := sql.Open("mysql", "mock:connection_string")
	if err != nil {
		t.Fatal(err)
	}

	// Call the handler function, passing in the mock request and response recorder
	handleLogin(db)(rr, req)

	// Check that the response status code is 200
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check that the response body contains the token
	expectedToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NzY4NjExMjgsInJvbGUiOiJhZG1pbiJ9.2KbYrEvgotQR_hypfaNYP4f3qRMjmrKz7CgmNxwYs88"
	if body := rr.Body.String(); !strings.Contains(body, expectedToken) {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expectedToken)
	}
}

func TestGenerateToken(t *testing.T) {
	expectedRole := "admin"
	expectedExpirationTime := time.Now().Add(time.Hour * 24).Unix()

	token, err := generateToken(expectedRole)
	if err != nil {
		t.Fatalf("Error generating token: %v", err)
	}

	// Parse the token to get the claims
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("my_secret_key"), nil
	})
	if err != nil {
		t.Fatalf("Error parsing token: %v", err)
	}

	// Verify the claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("Token claims are not of type MapClaims")
	}

	if role, ok := claims["role"].(string); !ok || role != expectedRole {
		t.Errorf("Token has unexpected role: %v", role)
	}

	if exp, ok := claims["exp"].(float64); !ok || int64(exp) != expectedExpirationTime {
		t.Errorf("Token has unexpected expiration time: %v", exp)
	}
}
