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
	"path/filepath"
	"sort"
	"strings"
	"time"

	"encoding/base64"

	"ars0n-framework-v2-server/utils"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

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
	utils.InitDB(dbPool)
	defer dbPool.Close()

	createTables()

	r := mux.NewRouter()

	// Apply CORS middleware first
	r.Use(corsMiddleware)

	// Define routes
	r.HandleFunc("/scopetarget/add", createScopeTarget).Methods("POST", "OPTIONS")
	r.HandleFunc("/scopetarget/read", readScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/delete/{id}", deleteScopeTarget).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/activate", activateScopeTarget).Methods("POST", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/amass", utils.GetAmassScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/run", utils.RunAmassScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/amass/{scanID}", utils.GetAmassScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/{scan_id}/dns", utils.GetDNSRecords).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/{scan_id}/ip", utils.GetIPs).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/{scan_id}/subdomain", utils.GetSubdomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/{scan_id}/cloud", utils.GetCloudDomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/{scan_id}/sp", utils.GetServiceProviders).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/{scan_id}/asn", utils.GetASNs).Methods("GET", "OPTIONS")
	r.HandleFunc("/amass/{scan_id}/subnet", utils.GetSubnets).Methods("GET", "OPTIONS")
	r.HandleFunc("/httpx/run", runHttpxScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/httpx/{scanID}", getHttpxScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/httpx", getHttpxScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans", getAllScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/gau/run", utils.RunGauScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/gau/{scanID}", utils.GetGauScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/gau", utils.GetGauScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/sublist3r/run", utils.RunSublist3rScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/sublist3r/{scan_id}", utils.GetSublist3rScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/sublist3r", utils.GetSublist3rScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/assetfinder/run", utils.RunAssetfinderScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/assetfinder/{scan_id}", utils.GetAssetfinderScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/assetfinder", utils.GetAssetfinderScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/ctl/run", utils.RunCTLScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/ctl/{scan_id}", utils.GetCTLScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/ctl", utils.GetCTLScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/subfinder/run", utils.RunSubfinderScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/subfinder/{scan_id}", utils.GetSubfinderScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/subfinder", utils.GetSubfinderScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/consolidate-subdomains/{id}", utils.HandleConsolidateSubdomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/consolidated-subdomains/{id}", utils.GetConsolidatedSubdomains).Methods("GET", "OPTIONS")
	r.HandleFunc("/shuffledns/run", utils.RunShuffleDNSScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/shuffledns/{scan_id}", utils.GetShuffleDNSScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/shuffledns", utils.GetShuffleDNSScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/cewl/run", utils.RunCeWLScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/cewl/{scan_id}", utils.GetCeWLScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/cewl", utils.GetCeWLScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/cewl-urls/run", utils.RunCeWLScansForUrls).Methods("POST", "OPTIONS")
	r.HandleFunc("/cewl-wordlist/run", utils.RunShuffleDNSWithWordlist).Methods("POST", "OPTIONS")
	r.HandleFunc("/cewl-wordlist/{scan_id}", utils.GetShuffleDNSScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/scope-targets/{id}/shufflednscustom-scans", utils.GetShuffleDNSCustomScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/gospider/run", utils.RunGoSpiderScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/gospider/{scan_id}", utils.GetGoSpiderScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/gospider", utils.GetGoSpiderScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/subdomainizer/run", utils.RunSubdomainizerScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/subdomainizer/{scan_id}", utils.GetSubdomainizerScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/subdomainizer", utils.GetSubdomainizerScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/nuclei-screenshot/run", runNucleiScreenshotScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/nuclei-screenshot/{scan_id}", getNucleiScreenshotScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/nuclei-screenshot", getNucleiScreenshotScansForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/nuclei-screenshot/run", runNucleiScreenshotScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/nuclei-screenshot/{scan_id}", getNucleiScreenshotScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/scope-targets/{id}/target-urls", getTargetURLsForScopeTarget).Methods("GET", "OPTIONS")
	r.HandleFunc("/metadata/run", utils.RunMetaDataScan).Methods("POST", "OPTIONS")
	r.HandleFunc("/metadata/{scan_id}", utils.GetMetaDataScanStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/scopetarget/{id}/scans/metadata", utils.GetMetaDataScansForScopeTarget).Methods("GET", "OPTIONS")

	log.Println("API server started on :8080")
	http.ListenAndServe(":8080", r)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
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

	query := `INSERT INTO scope_targets (type, mode, scope_target, active) VALUES ($1, $2, $3, $4)`
	_, err := dbPool.Exec(context.Background(), query, payload.Type, payload.Mode, payload.ScopeTarget, payload.Active)
	if err != nil {
		log.Printf("Error inserting into database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Request saved successfully"})
}

func readScopeTarget(w http.ResponseWriter, r *http.Request) {
	rows, err := dbPool.Query(context.Background(), `SELECT id, type, mode, scope_target, active FROM scope_targets`)
	if err != nil {
		log.Printf("Error querying database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []ResponsePayload
	for rows.Next() {
		var res ResponsePayload
		if err := rows.Scan(&res.ID, &res.Type, &res.Mode, &res.ScopeTarget, &res.Active); err != nil {
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

	query := `DELETE FROM scope_targets WHERE id = $1`
	_, err := dbPool.Exec(context.Background(), query, id)
	if err != nil {
		log.Printf("Error deleting from database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Request deleted successfully"})
}

func runHttpxScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		FQDN string `json:"fqdn" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.FQDN == "" {
		http.Error(w, "Invalid request body. `fqdn` is required.", http.StatusBadRequest)
		return
	}

	domain := payload.FQDN
	wildcardDomain := fmt.Sprintf("*.%s", domain)

	// Get the scope target ID
	query := `SELECT id FROM scope_targets WHERE type = 'Wildcard' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s", domain)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}

	// Get consolidated subdomains
	query = `SELECT subdomain FROM consolidated_subdomains WHERE scope_target_id = $1`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get consolidated subdomains: %v", err)
		http.Error(w, "Failed to get consolidated subdomains.", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var domainsToScan []string
	for rows.Next() {
		var subdomain string
		if err := rows.Scan(&subdomain); err != nil {
			log.Printf("[ERROR] Failed to scan subdomain row: %v", err)
			continue
		}
		domainsToScan = append(domainsToScan, subdomain)
	}

	// If no consolidated subdomains found, use the base domain
	if len(domainsToScan) == 0 {
		log.Printf("[INFO] No consolidated subdomains found, using base domain: %s", domain)
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO httpx_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go executeAndParseHttpxScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func executeAndParseHttpxScan(scanID, domain string) {
	log.Printf("[INFO] Starting httpx scan for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	// Check if container exists and is running
	containerName := "ars0n-framework-v2-httpx-1"

	// First check if container exists at all
	psCmd := exec.Command("docker", "ps", "-a", "-q", "-f", fmt.Sprintf("name=%s", containerName))
	var (
		output []byte
		err    error
	)
	output, err = psCmd.Output()
	if err != nil {
		log.Printf("[ERROR] Failed to check container existence: %v", err)
		updateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to check container existence: %v", err), "", time.Since(startTime).String())
		return
	}

	if len(output) == 0 {
		log.Printf("[ERROR] Container %s does not exist", containerName)
		updateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Container %s does not exist. Please ensure the container is created.", containerName), "", time.Since(startTime).String())
		return
	}

	// Now check if it's running
	checkCmd := exec.Command("docker", "ps", "-q", "-f", fmt.Sprintf("name=%s", containerName))
	output, err = checkCmd.Output()
	if err != nil || len(output) == 0 {
		log.Printf("[INFO] Container %s exists but is not running, attempting to start", containerName)
		// Try to start the container
		startCmd := exec.Command("docker", "start", containerName)
		var startStderr bytes.Buffer
		startCmd.Stderr = &startStderr
		if err := startCmd.Run(); err != nil {
			log.Printf("[ERROR] Failed to start container: %v", err)
			log.Printf("[ERROR] Start stderr: %s", startStderr.String())
			updateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to start container: %v\nStderr: %s", err, startStderr.String()), "", time.Since(startTime).String())
			return
		}
		log.Printf("[INFO] Successfully started container %s", containerName)
	}

	// Rest of the function remains the same...

	// Get scope target ID
	var scopeTargetID string
	err = dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id FROM httpx_scans WHERE scan_id = $1`,
		scanID).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scope target ID: %v", err)
		updateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to get scope target ID: %v", err), "", time.Since(startTime).String())
		return
	}

	// Get consolidated subdomains
	rows, err := dbPool.Query(context.Background(),
		`SELECT subdomain FROM consolidated_subdomains WHERE scope_target_id = $1`,
		scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get consolidated subdomains: %v", err)
		updateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to get consolidated subdomains: %v", err), "", time.Since(startTime).String())
		return
	}
	defer rows.Close()

	var domainsToScan []string
	for rows.Next() {
		var subdomain string
		if err := rows.Scan(&subdomain); err != nil {
			log.Printf("[ERROR] Failed to scan subdomain row: %v", err)
			continue
		}
		domainsToScan = append(domainsToScan, subdomain)
	}

	// If no consolidated subdomains found, use the base domain
	if len(domainsToScan) == 0 {
		log.Printf("[INFO] No consolidated subdomains found, using base domain: %s", domain)
		domainsToScan = []string{domain}
	}

	log.Printf("[INFO] Found %d domains to scan", len(domainsToScan))

	// Create temporary directory for domains file
	tempDir := "/tmp/httpx-temp"
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		log.Printf("[ERROR] Failed to create temp directory: %v", err)
		updateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create temp directory: %v", err), "", time.Since(startTime).String())
		return
	}
	defer os.RemoveAll(tempDir)

	// Write domains to file
	domainsFile := filepath.Join(tempDir, "domains.txt")
	if err := os.WriteFile(domainsFile, []byte(strings.Join(domainsToScan, "\n")), 0644); err != nil {
		log.Printf("[ERROR] Failed to write domains file: %v", err)
		updateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to write domains file: %v", err), "", time.Since(startTime).String())
		return
	}

	// Create directory in container
	mkdirCmd := exec.Command(
		"docker", "exec",
		containerName,
		"sh", "-c", "mkdir -p /tmp && chmod 777 /tmp",
	)
	var mkdirStderr bytes.Buffer
	mkdirCmd.Stderr = &mkdirStderr
	if err := mkdirCmd.Run(); err != nil {
		log.Printf("[ERROR] Failed to create directory in container: %v", err)
		log.Printf("[ERROR] mkdir stderr: %s", mkdirStderr.String())
		updateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create directory in container: %v\nStderr: %s", err, mkdirStderr.String()), "", time.Since(startTime).String())
		return
	}

	// Copy file to container
	copyCmd := exec.Command("docker", "cp", domainsFile, fmt.Sprintf("%s:/tmp/domains.txt", containerName))
	var copyStderr bytes.Buffer
	copyCmd.Stderr = &copyStderr
	if err := copyCmd.Run(); err != nil {
		log.Printf("[ERROR] Failed to copy domains file to container: %v", err)
		log.Printf("[ERROR] Copy stderr: %s", copyStderr.String())
		updateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to copy domains file to container: %v\nStderr: %s", err, copyStderr.String()), "", time.Since(startTime).String())
		return
	}

	// Verify file exists in container
	lsCmd := exec.Command(
		"docker", "exec",
		containerName,
		"ls", "-l", "/tmp/domains.txt",
	)
	var lsStderr bytes.Buffer
	lsCmd.Stderr = &lsStderr
	if err := lsCmd.Run(); err != nil {
		log.Printf("[ERROR] Failed to verify file in container: %v", err)
		log.Printf("[ERROR] ls stderr: %s", lsStderr.String())
		updateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to verify file in container: %v\nStderr: %s", err, lsStderr.String()), "", time.Since(startTime).String())
		return
	}

	// Run httpx in container
	cmd := exec.Command(
		"docker", "exec",
		containerName,
		"httpx",
		"-l", "/tmp/domains.txt",
		"-json",
		"-status-code",
		"-title",
		"-tech-detect",
		"-server",
		"-content-length",
		"-no-color",
		"-timeout", "10",
		"-retries", "2",
		"-mc", "100,101,200,201,202,203,204,205,206,207,208,226,300,301,302,303,304,305,307,308,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,421,422,423,424,426,428,429,431,451,500,501,502,503,504,505,506,507,508,510,511",
		"-o", "/tmp/httpx-output.json",
	)

	log.Printf("[INFO] Executing command: %s", cmd.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] httpx scan failed for %s: %v", domain, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		updateHttpxScanStatus(scanID, "error", "", stderr.String(), cmd.String(), execTime)
		return
	}

	// Read the output file from container
	outputCmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-httpx-1",
		"cat", "/tmp/httpx-output.json",
	)
	output, err = outputCmd.Output()
	if err != nil {
		log.Printf("[ERROR] Failed to read output file: %v", err)
		updateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to read output file: %v", err), cmd.String(), execTime)
		return
	}

	result := string(output)
	log.Printf("[INFO] httpx scan completed in %s for domain %s", execTime, domain)
	log.Printf("[DEBUG] Raw output length: %d bytes", len(result))
	if stderr.Len() > 0 {
		log.Printf("[DEBUG] stderr output: %s", stderr.String())
	}

	if result == "" {
		log.Printf("[WARN] No output from httpx scan")
		updateHttpxScanStatus(scanID, "completed", "", "No results found", cmd.String(), execTime)
	} else {
		log.Printf("[DEBUG] httpx output: %s", result)

		// Process results and update target URLs
		var liveURLs []string
		lines := strings.Split(result, "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}

			var httpxResult map[string]interface{}
			if err := json.Unmarshal([]byte(line), &httpxResult); err != nil {
				log.Printf("[WARN] Failed to parse httpx result line: %v", err)
				continue
			}

			if url, ok := httpxResult["url"].(string); ok {
				liveURLs = append(liveURLs, url)
				if err := updateTargetURLFromHttpx(scopeTargetID, httpxResult); err != nil {
					log.Printf("[WARN] Failed to update target URL for %s: %v", url, err)
				}
			}
		}

		// Mark URLs not found in this scan as no longer live
		if err := markOldTargetURLsAsNoLongerLive(scopeTargetID, liveURLs); err != nil {
			log.Printf("[WARN] Failed to mark old target URLs as no longer live: %v", err)
		}

		updateHttpxScanStatus(scanID, "success", result, stderr.String(), cmd.String(), execTime)
	}

	// Cleanup
	exec.Command("docker", "exec", "ars0n-framework-v2-httpx-1", "rm", "-f", "/tmp/domains.txt", "/tmp/httpx-output.json").Run()

	log.Printf("[INFO] Scan status updated for scan %s", scanID)
}

func updateHttpxScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating httpx scan status for %s to %s", scanID, status)
	query := `UPDATE httpx_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update httpx scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated httpx scan status for %s", scanID)
	}
}

func getHttpxScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scanID"]
	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	var scan utils.HttpxScanStatus
	query := `SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at FROM httpx_scans WHERE scan_id = $1`
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
		log.Printf("[ERROR] Failed to fetch httpx scan status: %v", err)
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

func getHttpxScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	query := `SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at 
              FROM httpx_scans WHERE scope_target_id = $1`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch scans for scope target ID %s: %v", scopeTargetID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan utils.HttpxScanStatus
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

func activateScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		http.Error(w, "ID is required in the path", http.StatusBadRequest)
		return
	}

	// Start a transaction
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		log.Printf("[ERROR] Failed to begin transaction: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	// First, deactivate all scope targets
	_, err = tx.Exec(context.Background(), `UPDATE scope_targets SET active = false`)
	if err != nil {
		log.Printf("[ERROR] Failed to deactivate scope targets: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Then, activate the selected scope target
	result, err := tx.Exec(context.Background(), `UPDATE scope_targets SET active = true WHERE id = $1`, id)
	if err != nil {
		log.Printf("[ERROR] Failed to activate scope target: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Scope target not found", http.StatusNotFound)
		return
	}

	// Commit the transaction
	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("[ERROR] Failed to commit transaction: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Scope target activated successfully"})
}

func getAllScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	// Query for Amass scans
	amassQuery := `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at 
		FROM amass_scans 
		WHERE scope_target_id = $1
	`
	amassRows, err := dbPool.Query(context.Background(), amassQuery, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch Amass scans: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer amassRows.Close()

	// Query for httpx scans
	httpxQuery := `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at 
		FROM httpx_scans 
		WHERE scope_target_id = $1
	`
	httpxRows, err := dbPool.Query(context.Background(), httpxQuery, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch httpx scans: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer httpxRows.Close()

	// Query for GAU scans
	gauQuery := `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at 
		FROM gau_scans 
		WHERE scope_target_id = $1
	`
	gauRows, err := dbPool.Query(context.Background(), gauQuery, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch GAU scans: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer gauRows.Close()

	var allScans []ScanSummary

	// Process Amass scans
	for amassRows.Next() {
		var scan utils.AmassScanStatus
		err := amassRows.Scan(
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
			log.Printf("[ERROR] Failed to scan Amass row: %v", err)
			continue
		}

		allScans = append(allScans, ScanSummary{
			ID:        scan.ID,
			ScanID:    scan.ScanID,
			Domain:    scan.Domain,
			Status:    scan.Status,
			Result:    nullStringToString(scan.Result),
			Error:     nullStringToString(scan.Error),
			StdOut:    nullStringToString(scan.StdOut),
			StdErr:    nullStringToString(scan.StdErr),
			Command:   nullStringToString(scan.Command),
			ExecTime:  nullStringToString(scan.ExecTime),
			CreatedAt: scan.CreatedAt,
			ScanType:  "amass",
		})
	}

	// Process httpx scans
	for httpxRows.Next() {
		var scan utils.HttpxScanStatus
		err := httpxRows.Scan(
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
			log.Printf("[ERROR] Failed to scan httpx row: %v", err)
			continue
		}

		allScans = append(allScans, ScanSummary{
			ID:        scan.ID,
			ScanID:    scan.ScanID,
			Domain:    scan.Domain,
			Status:    scan.Status,
			Result:    nullStringToString(scan.Result),
			Error:     nullStringToString(scan.Error),
			StdOut:    nullStringToString(scan.StdOut),
			StdErr:    nullStringToString(scan.StdErr),
			Command:   nullStringToString(scan.Command),
			ExecTime:  nullStringToString(scan.ExecTime),
			CreatedAt: scan.CreatedAt,
			ScanType:  "httpx",
		})
	}

	// Process GAU scans
	for gauRows.Next() {
		var scan utils.GauScanStatus
		err := gauRows.Scan(
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
			log.Printf("[ERROR] Failed to scan GAU row: %v", err)
			continue
		}

		allScans = append(allScans, ScanSummary{
			ID:        scan.ID,
			ScanID:    scan.ScanID,
			Domain:    scan.Domain,
			Status:    scan.Status,
			Result:    nullStringToString(scan.Result),
			Error:     nullStringToString(scan.Error),
			StdOut:    nullStringToString(scan.StdOut),
			StdErr:    nullStringToString(scan.StdErr),
			Command:   nullStringToString(scan.Command),
			ExecTime:  nullStringToString(scan.ExecTime),
			CreatedAt: scan.CreatedAt,
			ScanType:  "gau",
		})
	}

	// Sort all scans by creation date, newest first
	sort.Slice(allScans, func(i, j int) bool {
		return allScans[i].CreatedAt.After(allScans[j].CreatedAt)
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(allScans)
}

func runNucleiScreenshotScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	log.Printf("[INFO] Starting Nuclei screenshot scan for scope target ID: %s", scopeTargetID)

	// Generate a unique scan ID
	scanID := uuid.New().String()
	log.Printf("[INFO] Generated scan ID: %s", scanID)

	// Get domain from scope target
	var domain string
	err := dbPool.QueryRow(context.Background(),
		`SELECT TRIM(LEADING '*.' FROM scope_target) FROM scope_targets WHERE id = $1`,
		scopeTargetID).Scan(&domain)
	if err != nil {
		log.Printf("[ERROR] Failed to get domain: %v", err)
		http.Error(w, "Failed to get domain", http.StatusInternalServerError)
		return
	}

	// Insert initial scan record
	insertQuery := `INSERT INTO nuclei_screenshots (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to insert scan record for scope target %s: %v", scopeTargetID, err)
		http.Error(w, fmt.Sprintf("Failed to insert scan record: %v", err), http.StatusInternalServerError)
		return
	}
	log.Printf("[INFO] Successfully inserted initial scan record for scan ID: %s", scanID)

	// Start the scan in a goroutine
	go executeAndParseNucleiScreenshotScan(scanID, domain)

	// Return the scan ID to the client
	json.NewEncoder(w).Encode(map[string]string{
		"scan_id": scanID,
	})
}

func executeAndParseNucleiScreenshotScan(scanID, domain string) {
	_ = domain
	log.Printf("[INFO] Starting Nuclei screenshot scan execution for scan ID: %s", scanID)
	startTime := time.Now()

	// Get scope target ID and latest httpx results
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id FROM nuclei_screenshots WHERE scan_id = $1`,
		scanID).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scope target ID: %v", err)
		updateNucleiScreenshotScanStatus(scanID, "error", "", fmt.Sprintf("Failed to get scope target ID: %v", err), "", time.Since(startTime).String())
		return
	}

	// Get latest httpx results
	var httpxResults string
	err = dbPool.QueryRow(context.Background(), `
		SELECT result 
		FROM httpx_scans 
		WHERE scope_target_id = $1 
		AND status = 'success' 
		ORDER BY created_at DESC 
		LIMIT 1`, scopeTargetID).Scan(&httpxResults)
	if err != nil {
		log.Printf("[ERROR] Failed to get httpx results: %v", err)
		updateNucleiScreenshotScanStatus(scanID, "error", "", fmt.Sprintf("Failed to get httpx results: %v", err), "", time.Since(startTime).String())
		return
	}

	// Create a temporary file for URLs
	tempFile, err := os.CreateTemp("", "urls-*.txt")
	if err != nil {
		log.Printf("[ERROR] Failed to create temp file for scan ID %s: %v", scanID, err)
		updateNucleiScreenshotScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create temp file: %v", err), "", time.Since(startTime).String())
		return
	}
	defer os.Remove(tempFile.Name())
	log.Printf("[INFO] Created temporary file for URLs: %s", tempFile.Name())

	// Process httpx results and write URLs to temp file
	var urls []string
	for _, line := range strings.Split(httpxResults, "\n") {
		if line == "" {
			continue
		}
		var result struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			log.Printf("[WARN] Failed to parse httpx result line for scan ID %s: %v", scanID, err)
			continue
		}
		if result.URL != "" {
			urls = append(urls, result.URL)
		}
	}

	log.Printf("[INFO] Processed %d URLs for scan ID: %s", len(urls), scanID)

	if len(urls) == 0 {
		log.Printf("[ERROR] No valid URLs found in httpx results for scan ID: %s", scanID)
		updateNucleiScreenshotScanStatus(scanID, "error", "", "No valid URLs found in httpx results", "", time.Since(startTime).String())
		return
	}

	// Write URLs to temp file
	if err := os.WriteFile(tempFile.Name(), []byte(strings.Join(urls, "\n")), 0644); err != nil {
		log.Printf("[ERROR] Failed to write URLs to temp file for scan ID %s: %v", scanID, err)
		updateNucleiScreenshotScanStatus(scanID, "error", "", fmt.Sprintf("Failed to write URLs to temp file: %v", err), "", time.Since(startTime).String())
		return
	}
	log.Printf("[INFO] Successfully wrote %d URLs to temp file for scan ID: %s", len(urls), scanID)

	// Prepare docker command
	cmd := exec.Command(
		"docker", "exec", "ars0n-framework-v2-nuclei-1",
		"bash", "-c",
		fmt.Sprintf("cp %s /urls.txt && nuclei -t /root/nuclei-templates/headless/screenshot.yaml -list /urls.txt -headless", tempFile.Name()),
	)
	log.Printf("[INFO] Prepared Nuclei command for scan ID %s: %s", scanID, cmd.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the command
	log.Printf("[INFO] Executing Nuclei command for scan ID: %s", scanID)
	err = cmd.Run()
	if err != nil {
		log.Printf("[ERROR] Nuclei command failed for scan ID %s: %v", scanID, err)
		updateNucleiScreenshotScanStatus(
			scanID,
			"error",
			stdout.String(),
			fmt.Sprintf("Command failed: %v\nStderr: %s", err, stderr.String()),
			cmd.String(),
			time.Since(startTime).String(),
		)
		return
	}

	log.Printf("[INFO] Successfully completed Nuclei scan for scan ID: %s", scanID)
	log.Printf("[INFO] Scan duration for %s: %s", scanID, time.Since(startTime).String())

	// Read and process screenshot files
	var results []string
	screenshotFiles, err := exec.Command("docker", "exec", "ars0n-framework-v2-nuclei-1", "ls", "/app/screenshots/").Output()
	if err != nil {
		log.Printf("[ERROR] Failed to list screenshot files for scan ID %s: %v", scanID, err)
		updateNucleiScreenshotScanStatus(
			scanID,
			"error",
			"",
			fmt.Sprintf("Failed to list screenshot files: %v", err),
			cmd.String(),
			time.Since(startTime).String(),
		)
		return
	}

	for _, file := range strings.Split(string(screenshotFiles), "\n") {
		if file == "" || !strings.HasSuffix(file, ".png") {
			continue
		}

		// Read the screenshot file
		imgData, err := exec.Command("docker", "exec", "ars0n-framework-v2-nuclei-1", "cat", "/app/screenshots/"+file).Output()
		if err != nil {
			log.Printf("[WARN] Failed to read screenshot file %s: %v", file, err)
			continue
		}

		// Convert the URL-safe filename back to a real URL
		url := strings.TrimSuffix(file, ".png")
		url = strings.ReplaceAll(url, "__", "://")
		url = strings.ReplaceAll(url, "_", ".")

		// Normalize the URL
		url = utils.NormalizeURL(url)
		log.Printf("[DEBUG] Looking for target URL: %s", url)

		// Update target URL with screenshot
		screenshot := base64.StdEncoding.EncodeToString(imgData)
		if err := updateTargetURLFromScreenshot(url, screenshot); err != nil {
			log.Printf("[WARN] Failed to update target URL screenshot for %s: %v", url, err)
		}

		// Create the result object for the scan results
		result := struct {
			Matched    string `json:"matched"`
			Screenshot string `json:"screenshot"`
			Timestamp  string `json:"timestamp"`
		}{
			Matched:    url,
			Screenshot: screenshot,
			Timestamp:  time.Now().Format(time.RFC3339),
		}

		// Convert to JSON and add to results
		jsonResult, err := json.Marshal(result)
		if err != nil {
			log.Printf("[WARN] Failed to marshal screenshot result for %s: %v", url, err)
			continue
		}
		results = append(results, string(jsonResult))
	}

	// Update scan status with results
	updateNucleiScreenshotScanStatus(
		scanID,
		"success",
		strings.Join(results, "\n"),
		stderr.String(),
		cmd.String(),
		time.Since(startTime).String(),
	)

	// Clean up screenshots in the container
	exec.Command("docker", "exec", "ars0n-framework-v2-nuclei-1", "rm", "-rf", "/app/screenshots/*").Run()
}

func updateNucleiScreenshotScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating Nuclei screenshot scan status for %s to %s", scanID, status)
	query := `UPDATE nuclei_screenshots SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update Nuclei screenshot scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated Nuclei screenshot scan status for %s", scanID)
	}
}

func getNucleiScreenshotScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var scan NucleiScreenshotStatus
	query := `SELECT * FROM nuclei_screenshots WHERE scan_id = $1`
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
		&scan.ScopeTargetID,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[ERROR] Failed to get scan status: %v", err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	response := map[string]interface{}{
		"id":              scan.ID,
		"scan_id":         scan.ScanID,
		"domain":          scan.Domain,
		"status":          scan.Status,
		"result":          nullStringToString(scan.Result),
		"error":           nullStringToString(scan.Error),
		"stdout":          nullStringToString(scan.StdOut),
		"stderr":          nullStringToString(scan.StdErr),
		"command":         nullStringToString(scan.Command),
		"execution_time":  nullStringToString(scan.ExecTime),
		"created_at":      scan.CreatedAt.Format(time.RFC3339),
		"scope_target_id": scan.ScopeTargetID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func getNucleiScreenshotScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	query := `SELECT * FROM nuclei_screenshots WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan NucleiScreenshotStatus
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
			&scan.ScopeTargetID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":              scan.ID,
			"scan_id":         scan.ScanID,
			"domain":          scan.Domain,
			"status":          scan.Status,
			"result":          nullStringToString(scan.Result),
			"error":           nullStringToString(scan.Error),
			"stdout":          nullStringToString(scan.StdOut),
			"stderr":          nullStringToString(scan.StdErr),
			"command":         nullStringToString(scan.Command),
			"execution_time":  nullStringToString(scan.ExecTime),
			"created_at":      scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id": scan.ScopeTargetID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func updateTargetURLFromHttpx(scopeTargetID string, httpxData map[string]interface{}) error {
	url, ok := httpxData["url"].(string)
	if !ok || url == "" {
		return fmt.Errorf("invalid or missing URL in httpx data")
	}

	// Normalize the URL
	url = utils.NormalizeURL(url)
	log.Printf("[DEBUG] Processing httpx data for URL: %s", url)

	// Convert technologies interface{} to string array
	var technologies []string
	if techInterface, ok := httpxData["tech"].([]interface{}); ok {
		for _, tech := range techInterface {
			if techStr, ok := tech.(string); ok {
				technologies = append(technologies, techStr)
			}
		}
	}
	log.Printf("[DEBUG] Found technologies for %s: %v", url, technologies)

	// Check if target URL already exists
	var existingID string
	var isNoLongerLive bool
	err := dbPool.QueryRow(context.Background(),
		`SELECT id, no_longer_live FROM target_urls WHERE url = $1`,
		url).Scan(&existingID, &isNoLongerLive)

	if err == pgx.ErrNoRows {
		log.Printf("[DEBUG] Creating new target URL entry for: %s", url)
		// Insert new target URL with newly_discovered set to true
		_, err = dbPool.Exec(context.Background(),
			`INSERT INTO target_urls (
				url, status_code, title, web_server, technologies, 
				content_length, scope_target_id, newly_discovered, no_longer_live,
				findings_json
			) VALUES ($1, $2, $3, $4, $5::text[], $6, $7, true, false, $8::jsonb)`,
			url,
			httpxData["status_code"],
			httpxData["title"],
			httpxData["webserver"],
			technologies,
			httpxData["content_length"],
			scopeTargetID,
			"[]")
		if err != nil {
			return fmt.Errorf("failed to insert target URL: %v", err)
		}
		log.Printf("[DEBUG] Successfully created new target URL entry for: %s", url)
	} else if err == nil {
		log.Printf("[DEBUG] Updating existing target URL entry for: %s", url)

		var updateQuery string
		if isNoLongerLive {
			// If URL was previously marked as no longer live, mark it as newly discovered
			updateQuery = `UPDATE target_urls SET 
				status_code = $1,
				title = $2,
				web_server = $3,
				technologies = $4::text[],
				content_length = $5,
				no_longer_live = false,
				newly_discovered = true,
				updated_at = NOW(),
					findings_json = $6::jsonb
			WHERE id = $7`
		} else {
			// If URL was already live, just update its data and set newly_discovered to false
			updateQuery = `UPDATE target_urls SET 
				status_code = $1,
				title = $2,
				web_server = $3,
				technologies = $4::text[],
				content_length = $5,
				no_longer_live = false,
				newly_discovered = false,
				updated_at = NOW(),
				findings_json = $6::jsonb
			WHERE id = $7`
		}

		_, err = dbPool.Exec(context.Background(),
			updateQuery,
			httpxData["status_code"],
			httpxData["title"],
			httpxData["webserver"],
			technologies,
			httpxData["content_length"],
			"[]",
			existingID)
		if err != nil {
			return fmt.Errorf("failed to update target URL: %v", err)
		}
		log.Printf("[DEBUG] Successfully updated target URL entry for: %s", url)
	} else {
		return fmt.Errorf("error checking for existing target URL: %v", err)
	}

	return nil
}

func updateTargetURLFromScreenshot(url, screenshot string) error {
	log.Printf("[DEBUG] Updating screenshot for URL: %s", url)

	// Normalize the URL
	url = utils.NormalizeURL(url)

	// Check if target URL exists
	var existingID string
	err := dbPool.QueryRow(context.Background(),
		`SELECT id FROM target_urls WHERE url = $1`,
		url).Scan(&existingID)

	if err == pgx.ErrNoRows {
		log.Printf("[WARN] No target URL found for %s, cannot update screenshot", url)
		return fmt.Errorf("no target URL found for %s", url)
	} else if err != nil {
		return fmt.Errorf("error checking for existing target URL: %v", err)
	}

	// Update the screenshot
	_, err = dbPool.Exec(context.Background(),
		`UPDATE target_urls SET 
			screenshot = $1,
			updated_at = NOW()
		WHERE id = $2`,
		screenshot, existingID)

	if err != nil {
		return fmt.Errorf("failed to update target URL screenshot: %v", err)
	}

	log.Printf("[DEBUG] Successfully updated screenshot for URL: %s", url)
	return nil
}

func markOldTargetURLsAsNoLongerLive(scopeTargetID string, liveURLs []string) error {
	// Mark URLs that weren't found in this scan as no longer live
	_, err := dbPool.Exec(context.Background(),
		`UPDATE target_urls SET 
			no_longer_live = true,
			newly_discovered = false,
			updated_at = NOW()
		WHERE scope_target_id = $1 
		AND url NOT IN (SELECT unnest($2::text[]))`,
		scopeTargetID, liveURLs)

	if err != nil {
		return fmt.Errorf("failed to mark old target URLs as no longer live: %v", err)
	}
	return nil
}

func getTargetURLsForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	query := `
		SELECT id, url, screenshot, status_code, title, web_server, 
			   technologies, content_length, newly_discovered, no_longer_live,
			   scope_target_id, created_at, updated_at,
			   has_deprecated_tls, has_expired_ssl, has_mismatched_ssl,
			   has_revoked_ssl, has_self_signed_ssl, has_untrusted_root_ssl,
			   has_wildcard_tls, findings_json, http_response, http_response_headers,
			   dns_a_records, dns_aaaa_records, dns_cname_records, dns_mx_records,
			   dns_txt_records, dns_ns_records, dns_ptr_records, dns_srv_records
		FROM target_urls 
		WHERE scope_target_id = $1 
		ORDER BY created_at DESC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get target URLs: %v", err)
		http.Error(w, "Failed to get target URLs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var targetURLs []TargetURLResponse
	for rows.Next() {
		var targetURL TargetURL
		err := rows.Scan(
			&targetURL.ID,
			&targetURL.URL,
			&targetURL.Screenshot,
			&targetURL.StatusCode,
			&targetURL.Title,
			&targetURL.WebServer,
			&targetURL.Technologies,
			&targetURL.ContentLength,
			&targetURL.NewlyDiscovered,
			&targetURL.NoLongerLive,
			&targetURL.ScopeTargetID,
			&targetURL.CreatedAt,
			&targetURL.UpdatedAt,
			&targetURL.HasDeprecatedTLS,
			&targetURL.HasExpiredSSL,
			&targetURL.HasMismatchedSSL,
			&targetURL.HasRevokedSSL,
			&targetURL.HasSelfSignedSSL,
			&targetURL.HasUntrustedRootSSL,
			&targetURL.HasWildcardTLS,
			&targetURL.FindingsJSON,
			&targetURL.HTTPResponse,
			&targetURL.HTTPResponseHeaders,
			&targetURL.DNSARecords,
			&targetURL.DNSAAAARecords,
			&targetURL.DNSCNAMERecords,
			&targetURL.DNSMXRecords,
			&targetURL.DNSTXTRecords,
			&targetURL.DNSNSRecords,
			&targetURL.DNSPTRRecords,
			&targetURL.DNSSRVRecords,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan target URL row: %v", err)
			continue
		}

		// Convert to response type with proper handling of null values
		response := TargetURLResponse{
			ID:                  targetURL.ID,
			URL:                 targetURL.URL,
			Screenshot:          nullStringToString(targetURL.Screenshot),
			StatusCode:          targetURL.StatusCode,
			Title:               nullStringToString(targetURL.Title),
			WebServer:           nullStringToString(targetURL.WebServer),
			Technologies:        targetURL.Technologies,
			ContentLength:       targetURL.ContentLength,
			NewlyDiscovered:     targetURL.NewlyDiscovered,
			NoLongerLive:        targetURL.NoLongerLive,
			ScopeTargetID:       targetURL.ScopeTargetID,
			CreatedAt:           targetURL.CreatedAt,
			UpdatedAt:           targetURL.UpdatedAt,
			HasDeprecatedTLS:    targetURL.HasDeprecatedTLS,
			HasExpiredSSL:       targetURL.HasExpiredSSL,
			HasMismatchedSSL:    targetURL.HasMismatchedSSL,
			HasRevokedSSL:       targetURL.HasRevokedSSL,
			HasSelfSignedSSL:    targetURL.HasSelfSignedSSL,
			HasUntrustedRootSSL: targetURL.HasUntrustedRootSSL,
			HasWildcardTLS:      targetURL.HasWildcardTLS,
			FindingsJSON:        targetURL.FindingsJSON,
			HTTPResponse:        nullStringToString(targetURL.HTTPResponse),
			HTTPResponseHeaders: targetURL.HTTPResponseHeaders,
			DNSARecords:         targetURL.DNSARecords,
			DNSAAAARecords:      targetURL.DNSAAAARecords,
			DNSCNAMERecords:     targetURL.DNSCNAMERecords,
			DNSMXRecords:        targetURL.DNSMXRecords,
			DNSTXTRecords:       targetURL.DNSTXTRecords,
			DNSNSRecords:        targetURL.DNSNSRecords,
			DNSPTRRecords:       targetURL.DNSPTRRecords,
			DNSSRVRecords:       targetURL.DNSSRVRecords,
		}
		targetURLs = append(targetURLs, response)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(targetURLs)
}
