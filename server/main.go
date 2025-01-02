package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5/pgxpool"
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
	dbPool   *pgxpool.Pool
	enumType = map[string]bool{
		"Company":  true,
		"Wildcard": true,
		"URL":      true,
	}
	enumMode = map[string]bool{
		"Guided":    true,
		"Automated": true,
		"Hybrid":    true,
	}
)

func main() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Fatal("Environment variable DATABASE_URL is not set")
	}

	var err error
	for i := 0; i < 10; i++ {
		dbPool, err = pgxpool.New(context.Background(), connStr)
		if err == nil {
			err = dbPool.Ping(context.Background())
		}
		if err == nil {
			fmt.Println("Connected to the database successfully!")
			break
		}
		log.Printf("Failed to connect to the database: %v. Retrying in 5 seconds...", err)
		time.Sleep(5 * time.Second)
	}
	if err != nil {
		log.Fatalf("Could not connect to the database: %v", err)
	}
	defer dbPool.Close()

	createTable()

	r := mux.NewRouter()
	r.HandleFunc("/scopetarget/add", createScopeTarget).Methods("POST")
	r.HandleFunc("/scopetarget/read", readScopeTarget).Methods("GET")
	r.HandleFunc("/scopetarget/delete/{id}", deleteScopeTarget).Methods("DELETE")

	handlerWithCORS := corsMiddleware(r)

	log.Println("API server started on :8080")
	http.ListenAndServe(":8080", handlerWithCORS)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func createScopeTarget(w http.ResponseWriter, r *http.Request) {
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
	_, err := dbPool.Exec(context.Background(), query, payload.Type, payload.Mode, payload.ScopeTarget)
	if err != nil {
		log.Printf("Error inserting into database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Request saved successfully"})
}

func readScopeTarget(w http.ResponseWriter, r *http.Request) {
	rows, err := dbPool.Query(context.Background(), `SELECT id, type, mode, scope_target FROM requests`)
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

func deleteScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		http.Error(w, "ID is required in the path", http.StatusBadRequest)
		return
	}

	query := `DELETE FROM requests WHERE id = $1`
	_, err := dbPool.Exec(context.Background(), query, id)
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

	_, err := dbPool.Exec(context.Background(), query)
	if err != nil {
		log.Fatalf("Error creating table: %v", err)
	}
}
