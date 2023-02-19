package main

import (
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	// Open a connection to the database, connection string should be stored for example in AWS Secrets Manager or Azure Key Vault or any other suitable service
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
	http.ListenAndServe(":8080", nil)

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

// generateToken generates a JWT token for the given user ID and role
func generateToken(role string) (string, error) {
	// Create a new JWT token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set the claims for the token
	claims := token.Claims.(jwt.MapClaims)
	//claims["user_id"] = userID
	claims["role"] = role
	claims["exp"] = jwt.TimeFunc().Add(time.Hour * 24).Unix() // Token expires in 24 hours

	// Sign the token with a secret key
	secretKey := []byte("my_secret_key")
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	fmt.Println(token)
	return signedToken, nil
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
