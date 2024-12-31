package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5"
)

type RequestPayload struct {
	Type        string `json:"type"`
	Mode        string `json:"mode"`
	ScopeTarget string `json:"scope_target"`
}

var (
	dbConn   *pgx.Conn
	enumType = map[string]bool{
		"company":  true,
		"wildcard": true,
		"url":      true,
	}
	enumMode = map[string]bool{
		"manual":    true,
		"automated": true,
		"hybrid":    true,
	}
)

func main() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Fatal("Environment variable DATABASE_URL is not set")
	}

	var err error
	dbConn, err = pgx.Connect(context.Background(), connStr)
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}
	defer dbConn.Close(context.Background())

	createTable()

	http.HandleFunc("/scopetarget/add", createScopeTarget)
	log.Println("API server started on :8080")
	http.ListenAndServe(":8080", nil)
}

func createScopeTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload RequestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !enumType[payload.Type] {
		http.Error(w, "Invalid type value", http.StatusBadRequest)
		return
	}
	if !enumMode[payload.Mode] {
		http.Error(w, "Invalid mode value", http.StatusBadRequest)
		return
	}

	query := `INSERT INTO requests (type, mode, scope_target) VALUES ($1, $2, $3)`
	_, err := dbConn.Exec(context.Background(), query, payload.Type, payload.Mode, payload.ScopeTarget)
	if err != nil {
		log.Printf("Error inserting into database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Request saved successfully"})
}

func createTable() {
	query := `CREATE TABLE IF NOT EXISTS requests (
		id SERIAL PRIMARY KEY,
		type VARCHAR(50) NOT NULL,
		mode VARCHAR(50) NOT NULL,
		scope_target TEXT NOT NULL
	)`

	_, err := dbConn.Exec(context.Background(), query)
	if err != nil {
		log.Fatalf("Error creating table: %v", err)
	}
}
