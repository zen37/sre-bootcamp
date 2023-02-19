package main

import (
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	// Open a connection to the database
	// connection string should be retrieved from AWS Secrets Manager or Azure Key Vault or any other suitable service
	db, err := sql.Open("mysql", "secret:jOdznoyH6swQB9sTGdLUeeSrtejWkcw@tcp(sre-bootcamp-selection-challenge.cabf3yhjqvmq.us-east-1.rds.amazonaws.com:3306)/bootcamp_tht")
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	if err != nil {
		panic(err.Error())
	}

	fmt.Println("Connection successful!")

	// Start the HTTP server and handle requests
	http.HandleFunc("/login", handleLogin(db))
	http.HandleFunc("/protected", handleProtected)

	http.ListenAndServe(":8000", nil)

	//TestConnection(db)
}

func handleLogin(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the JSON request body
		var req struct {
			User     string `json:"username"`
			Password string `json:"password"`
		}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Verify the user's credentials against the database
		var hashedPassword, salt, role string
		var queryErr error
		err = db.QueryRow("SELECT password, salt, role FROM users WHERE username = ?", req.User).Scan(&hashedPassword, &salt, &role)
		if err != nil {
			queryErr = err
		}

		if queryErr == sql.ErrNoRows {
			fmt.Println("User not found")
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		} else if sha512Hash(req.Password+salt) == hashedPassword {
			// the username and password combination is valid
		} else {
			fmt.Println("Invalid combination of username or password")
			http.Error(w, "Invalid combination of username or password", http.StatusUnauthorized)
			return
		}

		// Generate a JWT token for the user
		token, err := generateToken(role)
		if err != nil {
			http.Error(w, "Error generating token", http.StatusInternalServerError)
			return
		}

		// Send the token in the response body
		resp := map[string]string{"token": token}
		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
			return
		}
	}
}

func handleProtected(w http.ResponseWriter, r *http.Request) {
	// Extract the JWT token from the Authorization header
	tokenString := extractToken(r)
	if tokenString == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse and verify the JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check that the signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// secret should be retrieved from AWS Secrets Manager or Azure Key Vault or any other suitable service
		secret := "my2w7wjd7yXF64FIADfJxNs1oupTGAuW"
		// Return the secret key used to sign the token
		return []byte(secret), nil
	})
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Check that the role claim in the JWT is equal to "admin"
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	role, ok := claims["role"].(string)
	if !ok || role != "admin" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// If the role claim in the JWT is equal to "admin", allow access to the protected resource
	fmt.Fprint(w, "Protected resource accessed successfully")
}

// generateToken generates a JWT token for the given user ID and role
func generateToken(role string) (string, error) {
	// secret should be retrieved from AWS Secrets Manager or Azure Key Vault or any other suitable service
	secret := "my2w7wjd7yXF64FIADfJxNs1oupTGAuW"
	// Create a new JWT token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set the claims for the token
	claims := token.Claims.(jwt.MapClaims)
	claims["role"] = role
	//claims["exp"] = jwt.TimeFunc().Add(time.Hour * 24).Unix() // Token expires in 24 hours

	// Sign the token with the secret key
	secretKey := []byte(secret)
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	token := strings.Replace(authHeader, "Bearer ", "", 1)
	return token
}

func sha512Hash(str string) string {
	// Convert the string to bytes
	data := []byte(str)

	// Create a new SHA-512 hash object
	hash := sha512.New()

	// Write the data to the hash object
	hash.Write(data)

	// Get the raw hashed bytes
	hashed := hash.Sum(nil)

	// Convert the hashed bytes to a hex string
	return hex.EncodeToString(hashed)
}

func TestConnection(db *sql.DB) {

	// Test the connection by fetching data from a table
	rows, err := db.Query("SELECT username, role, salt, password FROM users")
	if err != nil {
		panic(err.Error())
	}
	defer rows.Close()

	// Iterate over the rows and print the data
	for rows.Next() {
		var username, role, salt, pass string
		err = rows.Scan(&username, &role, &salt, &pass)
		if err != nil {
			panic(err.Error())
		}
		fmt.Printf("username: %s role: %s salt: %s pass: %s\n", username, role, salt, pass)
	}

	fmt.Println("Query successful!")
}
