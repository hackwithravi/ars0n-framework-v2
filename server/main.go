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

type ResponsePayload struct {
	ID          int    `json:"id"`
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
	http.HandleFunc("/scopetarget/read", readScopeTarget)
	http.HandleFunc("/scopetarget/update", updateScopeTarget)
	http.HandleFunc("/scopetarget/delete", deleteScopeTarget)

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

func readScopeTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := dbConn.Query(context.Background(), `SELECT id, type, mode, scope_target FROM requests`)
	if err != nil {
		log.Printf("Error querying database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []ResponsePayload
	for rows.Next() {
		var res ResponsePayload
		if err := rows.Scan(&res.ID, &res.Type, &res.Mode, &res.ScopeTarget); err != nil {
			log.Printf("Error scanning row: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		results = append(results, res)
	}

	json.NewEncoder(w).Encode(results)
}

func updateScopeTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Only PUT requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		ID          int    `json:"id"`
		Type        string `json:"type"`
		Mode        string `json:"mode"`
		ScopeTarget string `json:"scope_target"`
	}
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

	query := `UPDATE requests SET type = $1, mode = $2, scope_target = $3 WHERE id = $4`
	_, err := dbConn.Exec(context.Background(), query, payload.Type, payload.Mode, payload.ScopeTarget, payload.ID)
	if err != nil {
		log.Printf("Error updating database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Request updated successfully"})
}

func deleteScopeTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Only DELETE requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	query := `DELETE FROM requests WHERE id = $1`
	_, err := dbConn.Exec(context.Background(), query, payload.ID)
	if err != nil {
		log.Printf("Error deleting from database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Request deleted successfully"})
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
