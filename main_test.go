package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
)

func TestHandleLogin(t *testing.T) {
	// Define a test table
	tests := []struct {
		name           string
		username       string
		password       string
		expectedStatus int
		expectedToken  string
	}{
		{"Valid credentials", "bob", "thisIsNotAPasswordBob", http.StatusOK, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoidmlld2VyIn0.l7pxJXYHlJdtI9RME2UesMzuVjqf-RtzQeLTHomo_Ic"},
		{"Invalid username", "invaliduser", "testpassword", http.StatusUnauthorized, ""},
		{"Invalid password", "testuser", "invalidpassword", http.StatusUnauthorized, ""},
	}

	// connection string should be retrieved from AWS Secrets Manager or Azure Key Vault or any other suitable service
	db, err := sql.Open("mysql", "secret:jOdznoyH6swQB9sTGdLUeeSrtejWkcw@tcp(sre-bootcamp-selection-challenge.cabf3yhjqvmq.us-east-1.rds.amazonaws.com:3306)/bootcamp_tht")
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create a new request with a JSON request body
			reqBody := strings.NewReader(fmt.Sprintf(`{"username":"%s","password":"%s"}`, test.username, test.password))
			req, err := http.NewRequest("POST", "/login", reqBody)
			if err != nil {
				t.Fatal(err)
			}
			// Set the content type to JSON
			req.Header.Set("Content-Type", "application/json")

			// Create a new ResponseRecorder (which satisfies http.ResponseWriter) to capture the response
			rr := httptest.NewRecorder()

			// Call the handler function, passing in the mock request and response recorder
			handleLogin(db)(rr, req)

			// Check that the response status code is the expected status code
			if status := rr.Code; status != test.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, test.expectedStatus)
			}

			// Check that the response body contains a non-empty token (if the expected status code is OK)
			if test.expectedStatus == http.StatusOK {
				body := rr.Body.String()
				var response map[string]string
				err := json.Unmarshal([]byte(body), &response)
				if err != nil {
					t.Errorf("failed to unmarshal response body: %v", err)
				}
				actualToken := response["token"]
				if actualToken != test.expectedToken {
					t.Errorf("HandleLogin did not return the expected token for test case %q: got %q, want %q", test.name, actualToken, test.expectedToken)
				}
			}
		})
	}
}

func TestHandleProtected(t *testing.T) {
	// Test cases
	tests := []struct {
		name           string
		role           string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "admin user",
			role:           "admin",
			expectedStatus: http.StatusOK,
			expectedBody:   "Protected resource accessed successfully",
		},
		{
			name:           "non-admin user",
			role:           "user",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Unauthorized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start a test server with handleProtected as the handler
			testServer := httptest.NewServer(http.HandlerFunc(handleProtected))

			// Set up a request with a valid JWT token in the Authorization header
			req, err := http.NewRequest("GET", testServer.URL, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			token, err := generateToken(tt.role)
			if err != nil {
				t.Fatalf("Failed to generate token: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+token)

			// Send the request and get the response
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Failed to send request: %v", err)
			}
			defer resp.Body.Close()

			// Check that the response status code is as expected
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Unexpected status code: got %d, want %d", resp.StatusCode, tt.expectedStatus)
			}

			// Check that the response body contains the expected message
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}
			actualBody := strings.TrimSpace(string(bodyBytes))
			if actualBody != tt.expectedBody {
				t.Errorf("Unexpected response body: got %q, want %q", actualBody, tt.expectedBody)
			}

			testServer.Close()
		})
	}
}

func TestGenerateToken(t *testing.T) {
	// secret should be retrieved from AWS Secrets Manager or Azure Key Vault or any other suitable service
	secret := "my2w7wjd7yXF64FIADfJxNs1oupTGAuW"
	expectedRole := "admin"
	//expectedExpirationTime := time.Now().Add(time.Hour * 24).Unix()

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

		return []byte(secret), nil
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

	/*
		if exp, ok := claims["exp"].(float64); !ok || int64(exp) != expectedExpirationTime {
			t.Errorf("Token has unexpected expiration time: %v", exp)
		}
	*/
}
