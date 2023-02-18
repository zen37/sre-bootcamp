package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	http.HandleFunc("/login", handleLogin)
	http.ListenAndServe(":8080", nil)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check username and password against database or other authentication system.
	if user.Username == "admin" && user.Password == "password123" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Login successful!")
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid username or password.")
	}
}
