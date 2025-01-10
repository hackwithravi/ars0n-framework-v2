package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DNSRecord struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Record    string    `json:"record"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

type IPAddress struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Address   string    `json:"address"`
	CreatedAt time.Time `json:"created_at"`
}

type Subdomain struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Subdomain string    `json:"subdomain"`
	CreatedAt time.Time `json:"created_at"`
}

type RequestPayload struct {
	Type        string `json:"type"`
	Mode        string `json:"mode"`
	ScopeTarget string `json:"scope_target"`
}

type ResponsePayload struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Mode        string `json:"mode"`
	ScopeTarget string `json:"scope_target"`
}

type AmassScanStatus struct {
	ID        string         `json:"id"`
	ScanID    string         `json:"scan_id"`
	Domain    string         `json:"domain"`
	Status    string         `json:"status"`
	Result    sql.NullString `json:"result,omitempty"`
	Error     sql.NullString `json:"error,omitempty"`
	StdOut    sql.NullString `json:"stdout,omitempty"`
	StdErr    sql.NullString `json:"stderr,omitempty"`
	Command   sql.NullString `json:"command,omitempty"`
	ExecTime  sql.NullString `json:"execution_time,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

var dbPool *pgxpool.Pool

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

	createTables()

	r := mux.NewRouter()
	r.HandleFunc("/scopetarget/add", createScopeTarget).Methods("POST")
	r.HandleFunc("/scopetarget/read", readScopeTarget).Methods("GET")
	r.HandleFunc("/scopetarget/delete/{id}", deleteScopeTarget).Methods("DELETE")
	r.HandleFunc("/scopetarget/{id}/scans/amass", getAmassScansForScopeTarget).Methods("GET")
	r.HandleFunc("/amass/run", runAmassScan).Methods("POST")
	r.HandleFunc("/amass/{scanID}", getAmassScanStatus).Methods("GET")
	r.HandleFunc("/amass/{scan_id}/dns", getDNSRecords).Methods("GET")
	r.HandleFunc("/amass/{scan_id}/ip", getIPs).Methods("GET")
	r.HandleFunc("/amass/{scan_id}/subdomain", getSubdomains).Methods("GET")

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

func createTables() {
	queries := []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto;`,
		`CREATE TABLE IF NOT EXISTS requests (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			type VARCHAR(50) NOT NULL,
			mode VARCHAR(50) NOT NULL,
			scope_target TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS amass_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			request_id UUID REFERENCES requests(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS dns_records (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			record TEXT NOT NULL,
			record_type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS ips (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			ip_address TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS subdomains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			subdomain TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
	}

	for _, query := range queries {
		_, err := dbPool.Exec(context.Background(), query)
		if err != nil {
			log.Fatalf("Error creating table: %v", err)
		}
	}
}

func getAmassScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	query := `SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at 
              FROM amass_scans WHERE request_id = $1`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch scans for scope target ID %s: %v", scopeTargetID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan AmassScanStatus
		err := rows.Scan(
			&scan.ID,
			&scan.ScanID,
			&scan.Domain,
			&scan.Status,
			&scan.Result,
			&scan.Error,
			&scan.StdOut,
			&scan.StdErr,
			&scan.Command,
			&scan.ExecTime,
			&scan.CreatedAt,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		scans = append(scans, map[string]interface{}{
			"id":             scan.ID,
			"scan_id":        scan.ScanID,
			"domain":         scan.Domain,
			"status":         scan.Status,
			"result":         nullStringToString(scan.Result),
			"error":          nullStringToString(scan.Error),
			"stdout":         nullStringToString(scan.StdOut),
			"stderr":         nullStringToString(scan.StdErr),
			"command":        nullStringToString(scan.Command),
			"execution_time": nullStringToString(scan.ExecTime),
			"created_at":     scan.CreatedAt.Format(time.RFC3339),
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(scans)
}

func runAmassScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		FQDN string `json:"fqdn" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.FQDN == "" {
		http.Error(w, "Invalid request body. `fqdn` is required.", http.StatusBadRequest)
		return
	}

	domain := payload.FQDN
	wildcardDomain := fmt.Sprintf("*.%s", domain)

	query := `SELECT id FROM requests WHERE type = 'Wildcard' AND scope_target = $1`
	var requestID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&requestID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s", domain)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO amass_scans (scan_id, domain, status, request_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", requestID)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go executeAmassScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func executeAmassScan(scanID, domain string) {
	startTime := time.Now()
	cmd := exec.Command(
		"docker", "run", "--rm",
		"caffix/amass",
		"enum", "-active", "-alts", "-brute", "-nocolor",
		"-min-for-recursive", "2", "-timeout", "60",
		"-d", domain,
		"-r", "8.8.8.8", "1.1.1.1", "9.9.9.9", "64.6.64.6",
		"208.67.222.222", "208.67.220.220", "8.26.56.26", "8.20.247.20",
		"185.228.168.9", "185.228.169.9", "76.76.19.19", "76.223.122.150",
		"198.101.242.72", "176.103.130.130", "176.103.130.131",
		"94.140.14.14", "94.140.15.15", "1.0.0.1", "77.88.8.8", "77.88.8.1",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	status := "success"
	var result, errorMsg string
	if err != nil {
		status = "error"
		errorMsg = err.Error()
		log.Printf("[ERROR] Amass scan %s failed: %v\nStdout: %s\nStderr: %s\n", scanID, err, stdout.String(), stderr.String())
	} else {
		result = stdout.String()
		log.Printf("[SUCCESS] Amass scan %s completed successfully.\nStdout: %s\nStderr: %s\n", scanID, stdout.String(), stderr.String())

		parseAndStoreSubdomains(scanID, result)

		lines := strings.Split(result, "\n")
		dnsRecords := map[string][]string{
			"arecord":     {},
			"aaaarecord":  {},
			"cnamerecord": {},
			"mxrecord":    {},
			"txtrecord":   {},
			"node":        {},
			"nsrecord":    {},
			"srvrecord":   {},
			"ptrrecord":   {},
			"spfrecord":   {},
			"soarecord":   {},
		}
		var ipv4Addresses []string

		for _, line := range lines {
			if strings.Contains(line, "a_record") && !strings.Contains(line, "aaaa_record") {
				dnsRecords["arecord"] = append(dnsRecords["arecord"], line)
				insertDNSRecord(scanID, line, "A")
			}
			if strings.Contains(line, "aaaa_record") {
				dnsRecords["aaaarecord"] = append(dnsRecords["aaaarecord"], line)
				insertDNSRecord(scanID, line, "AAAA")
			}
			if strings.Contains(line, "cname_record") {
				dnsRecords["cnamerecord"] = append(dnsRecords["cnamerecord"], line)
				insertDNSRecord(scanID, line, "CNAME")
			}
			if strings.Contains(line, "mx_record") {
				dnsRecords["mxrecord"] = append(dnsRecords["mxrecord"], line)
				insertDNSRecord(scanID, line, "MX")
			}
			if strings.Contains(line, "txt_record") {
				dnsRecords["txtrecord"] = append(dnsRecords["txtrecord"], line)
				insertDNSRecord(scanID, line, "TXT")
			}
			if strings.Contains(line, "node") {
				dnsRecords["node"] = append(dnsRecords["node"], line)
				insertDNSRecord(scanID, line, "Node")
			}
			if strings.Contains(line, "ns_record") {
				dnsRecords["nsrecord"] = append(dnsRecords["nsrecord"], line)
				insertDNSRecord(scanID, line, "NS")
			}
			if strings.Contains(line, "srv_record") {
				dnsRecords["srvrecord"] = append(dnsRecords["srvrecord"], line)
				insertDNSRecord(scanID, line, "SRV")
			}
			if strings.Contains(line, "ptr_record") {
				dnsRecords["ptrrecord"] = append(dnsRecords["ptrrecord"], line)
				insertDNSRecord(scanID, line, "PTR")
			}
			if strings.Contains(line, "spf_record") {
				dnsRecords["spfrecord"] = append(dnsRecords["spfrecord"], line)
				insertDNSRecord(scanID, line, "SPF")
			}
			if strings.Contains(line, "soa_record") {
				dnsRecords["soarecord"] = append(dnsRecords["soarecord"], line)
				insertDNSRecord(scanID, line, "SOA")
			}
			if strings.Contains(line, "ipv4_address") {
				ipv4Addresses = append(ipv4Addresses, line)
				insertIP(scanID, line)
			}
		}

		log.Printf("DNS Records: %+v\n", dnsRecords)
		log.Printf("IPv4 Addresses: %+v\n", ipv4Addresses)
	}

	updateQuery := `UPDATE amass_scans SET status = $1, result = $2, error = $3, stdout = $4, stderr = $5, command = $6, execution_time = $7 WHERE scan_id = $8`
	_, dbErr := dbPool.Exec(context.Background(), updateQuery, status, result, errorMsg, stdout.String(), stderr.String(), cmd.String(), execTime, scanID)
	if dbErr != nil {
		log.Printf("[ERROR] Failed to update scan record: %v", dbErr)
	}
}

func parseAndStoreSubdomains(scanID, result string) {
	log.Printf("[DEBUG] Starting parseAndStoreSubdomains for scanID: %s", scanID)
	subdomainRegex := regexp.MustCompile(`([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
	lines := strings.Split(result, "\n")
	log.Printf("[DEBUG] Split result into %d lines", len(lines))

	var subdomains []string

	for i, line := range lines {
		log.Printf("[DEBUG] Processing line %d: %s", i+1, line)
		matches := subdomainRegex.FindAllString(line, -1)
		log.Printf("[DEBUG] Found %d matches in line %d", len(matches), i+1)
		for _, match := range matches {
			log.Printf("[DEBUG] Adding subdomain %s to list and database", match)
			subdomains = append(subdomains, match)
			insertSubdomain(scanID, match)
		}
	}

	log.Printf("[INFO] Parsed subdomains for scan %s: %v", scanID, subdomains)
}

func insertSubdomain(scanID, subdomain string) {
	log.Printf("[DEBUG] Attempting to insert subdomain %s for scanID: %s", subdomain, scanID)
	query := `INSERT INTO subdomains (scan_id, subdomain) VALUES ($1, $2)`
	_, err := dbPool.Exec(context.Background(), query, scanID, subdomain)
	if err != nil {
		log.Printf("[ERROR] Failed to insert subdomain %s for scan %s: %v", subdomain, scanID, err)
		return
	}
	log.Printf("[DEBUG] Successfully inserted subdomain %s for scanID: %s", subdomain, scanID)
}

func getAmassScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scanID"]
	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	var scan AmassScanStatus
	query := `SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at FROM amass_scans WHERE scan_id = $1`
	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID,
		&scan.ScanID,
		&scan.Domain,
		&scan.Status,
		&scan.Result,
		&scan.Error,
		&scan.StdOut,
		&scan.StdErr,
		&scan.Command,
		&scan.ExecTime,
		&scan.CreatedAt,
	)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch scan status: %v", err)
		http.Error(w, "Scan not found.", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"id":             scan.ID,
		"scan_id":        scan.ScanID,
		"domain":         scan.Domain,
		"status":         scan.Status,
		"result":         nullStringToString(scan.Result),
		"error":          nullStringToString(scan.Error),
		"stdout":         nullStringToString(scan.StdOut),
		"stderr":         nullStringToString(scan.StdErr),
		"command":        nullStringToString(scan.Command),
		"execution_time": nullStringToString(scan.ExecTime),
		"created_at":     scan.CreatedAt.Format(time.RFC3339),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func nullStringToString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

func createScopeTarget(w http.ResponseWriter, r *http.Request) {
	var payload RequestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
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

	w.WriteHeader(http.StatusOK)
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

func insertDNSRecord(scanID, record, recordType string) {
	query := `INSERT INTO dns_records (scan_id, record, record_type) VALUES ($1, $2, $3)`
	_, err := dbPool.Exec(context.Background(), query, scanID, record, recordType)
	if err != nil {
		log.Printf("Failed to insert DNS record: %v", err)
	}
}

func insertIP(scanID, ip string) {
	query := `INSERT INTO ips (scan_id, ip_address) VALUES ($1, $2)`
	_, err := dbPool.Exec(context.Background(), query, scanID, ip)
	if err != nil {
		log.Printf("Failed to insert IP address: %v", err)
	}
}

func getDNSRecords(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	query := `SELECT id, scan_id, record, record_type, created_at FROM dns_records WHERE scan_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch DNS records for scan %s: %v", scanID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var dnsRecords []DNSRecord
	for rows.Next() {
		var dnsRecord DNSRecord
		if err := rows.Scan(&dnsRecord.ID, &dnsRecord.ScanID, &dnsRecord.Record, &dnsRecord.Type, &dnsRecord.CreatedAt); err != nil {
			log.Printf("[ERROR] Failed to scan DNS record row: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		dnsRecords = append(dnsRecords, dnsRecord)
	}

	if err := rows.Err(); err != nil {
		log.Printf("[ERROR] Error iterating over rows: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(dnsRecords); err != nil {
		log.Printf("[ERROR] Failed to encode DNS records: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func getIPs(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	query := `SELECT ip_address FROM ips WHERE scan_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		http.Error(w, "Failed to fetch IPs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			http.Error(w, "Error scanning IP", http.StatusInternalServerError)
			return
		}
		ips = append(ips, ip)
	}
	json.NewEncoder(w).Encode(ips)
}

func getSubdomains(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	query := `SELECT subdomain FROM subdomains WHERE scan_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch subdomains for scan %s: %v", scanID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var subdomains []string
	for rows.Next() {
		var subdomain string
		if err := rows.Scan(&subdomain); err != nil {
			log.Printf("[ERROR] Failed to scan subdomain row: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		subdomains = append(subdomains, subdomain)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(subdomains)
}
