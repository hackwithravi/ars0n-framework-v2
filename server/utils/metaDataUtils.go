package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

type MetaDataStatus struct {
	ID            string         `json:"id"`
	ScanID        string         `json:"scan_id"`
	Domain        string         `json:"domain"`
	Status        string         `json:"status"`
	Result        sql.NullString `json:"result,omitempty"`
	Error         sql.NullString `json:"error,omitempty"`
	StdOut        sql.NullString `json:"stdout,omitempty"`
	StdErr        sql.NullString `json:"stderr,omitempty"`
	Command       sql.NullString `json:"command,omitempty"`
	ExecTime      sql.NullString `json:"execution_time,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	ScopeTargetID string         `json:"scope_target_id"`
}

type DNSResults struct {
	ARecords     []string
	AAAARecords  []string
	CNAMERecords []string
	MXRecords    []string
	TXTRecords   []string
	NSRecords    []string
	PTRRecords   []string
	SRVRecords   []string
}

func NormalizeURL(url string) string {
	// Fix double colon issue
	url = strings.ReplaceAll(url, "https:://", "https://")
	url = strings.ReplaceAll(url, "http:://", "http://")

	// Ensure URL has proper scheme
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	return url
}

func SanitizeResponse(input []byte) string {
	// Remove null bytes
	sanitized := bytes.ReplaceAll(input, []byte{0}, []byte{})

	// Convert to string and handle any invalid UTF-8
	str := string(sanitized)

	// Replace any other problematic characters
	str = strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return -1 // Drop the character
		}
		return r
	}, str)

	return str
}

func RunMetaDataScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		ScopeTargetID string `json:"scope_target_id" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.ScopeTargetID == "" {
		http.Error(w, "Invalid request body. `scope_target_id` is required.", http.StatusBadRequest)
		return
	}

	// Get domain from scope target
	var domain string
	err := dbPool.QueryRow(context.Background(),
		`SELECT TRIM(LEADING '*.' FROM scope_target) FROM scope_targets WHERE id = $1`,
		payload.ScopeTargetID).Scan(&domain)
	if err != nil {
		log.Printf("[ERROR] Failed to get domain: %v", err)
		http.Error(w, "Failed to get domain", http.StatusInternalServerError)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO metadata_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", payload.ScopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseMetaDataScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseMetaDataScan(scanID, domain string) {
	log.Printf("[INFO] Starting Nuclei SSL scan for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	// Get scope target ID and latest httpx results
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id FROM metadata_scans WHERE scan_id = $1`,
		scanID).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scope target ID: %v", err)
		UpdateMetaDataScanStatus(scanID, "error", "", fmt.Sprintf("Failed to get scope target ID: %v", err), "", time.Since(startTime).String())
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
		UpdateMetaDataScanStatus(scanID, "error", "", fmt.Sprintf("Failed to get httpx results: %v", err), "", time.Since(startTime).String())
		return
	}

	// Create a temporary file for URLs
	tempFile, err := os.CreateTemp("", "urls-*.txt")
	if err != nil {
		log.Printf("[ERROR] Failed to create temp file for scan ID %s: %v", scanID, err)
		UpdateMetaDataScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create temp file: %v", err), "", time.Since(startTime).String())
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
		if result.URL != "" && strings.HasPrefix(result.URL, "https://") {
			urls = append(urls, result.URL)
		}
	}

	if len(urls) == 0 {
		log.Printf("[ERROR] No valid HTTPS URLs found in httpx results for scan ID: %s", scanID)
		UpdateMetaDataScanStatus(scanID, "error", "", "No valid HTTPS URLs found in httpx results", "", time.Since(startTime).String())
		return
	}

	// Write URLs to temp file
	if err := os.WriteFile(tempFile.Name(), []byte(strings.Join(urls, "\n")), 0644); err != nil {
		log.Printf("[ERROR] Failed to write URLs to temp file for scan ID %s: %v", scanID, err)
		UpdateMetaDataScanStatus(scanID, "error", "", fmt.Sprintf("Failed to write URLs to temp file: %v", err), "", time.Since(startTime).String())
		return
	}
	log.Printf("[INFO] Successfully wrote %d URLs to temp file for scan ID: %s", len(urls), scanID)

	// Copy the URLs file into the container
	copyCmd := exec.Command(
		"docker", "cp",
		tempFile.Name(),
		"ars0n-framework-v2-nuclei-1:/urls.txt",
	)
	if err := copyCmd.Run(); err != nil {
		log.Printf("[ERROR] Failed to copy URLs file to container: %v", err)
		UpdateMetaDataScanStatus(scanID, "error", "", fmt.Sprintf("Failed to copy URLs file: %v", err), "", time.Since(startTime).String())
		return
	}

	// Run all templates in one scan with JSON output
	cmd := exec.Command(
		"docker", "exec", "ars0n-framework-v2-nuclei-1",
		"nuclei",
		"-t", "/root/nuclei-templates/ssl/",
		"-list", "/urls.txt",
		"-j",
		"-o", "/output.json",
	)
	log.Printf("[INFO] Executing command: %s", cmd.String())

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		log.Printf("[ERROR] Nuclei scan failed: %v", err)
		UpdateMetaDataScanStatus(scanID, "error", "", stderr.String(), cmd.String(), time.Since(startTime).String())
		return
	}

	// Read the JSON output file
	outputCmd := exec.Command(
		"docker", "exec", "ars0n-framework-v2-nuclei-1",
		"cat", "/output.json",
	)
	output, err := outputCmd.Output()
	if err != nil {
		log.Printf("[ERROR] Failed to read output file: %v", err)
		UpdateMetaDataScanStatus(scanID, "error", "", fmt.Sprintf("Failed to read output file: %v", err), cmd.String(), time.Since(startTime).String())
		return
	}

	// Process each finding and update the database
	findings := strings.Split(string(output), "\n")
	for _, finding := range findings {
		if finding == "" {
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal([]byte(finding), &result); err != nil {
			log.Printf("[ERROR] Failed to parse JSON finding: %v", err)
			continue
		}

		templateID, ok := result["template-id"].(string)
		if !ok {
			continue
		}

		matchedURL, ok := result["matched-at"].(string)
		if !ok {
			continue
		}

		// Convert matched-at (host:port) to URL
		url := "https://" + strings.TrimSuffix(matchedURL, ":443")

		// Update the target_urls table based on the template
		var updateField string
		switch templateID {
		case "deprecated-tls":
			updateField = "has_deprecated_tls"
		case "expired-ssl":
			updateField = "has_expired_ssl"
		case "mismatched-ssl-certificate":
			updateField = "has_mismatched_ssl"
		case "revoked-ssl-certificate":
			updateField = "has_revoked_ssl"
		case "self-signed-ssl":
			updateField = "has_self_signed_ssl"
		case "untrusted-root-certificate":
			updateField = "has_untrusted_root_ssl"
		default:
			continue
		}

		query := fmt.Sprintf("UPDATE target_urls SET %s = true WHERE url = $1 AND scope_target_id = $2", updateField)
		commandTag, err := dbPool.Exec(context.Background(), query, url, scopeTargetID)
		if err != nil {
			log.Printf("[ERROR] Failed to update target URL %s for template %s: %v", url, templateID, err)
		} else {
			rowsAffected := commandTag.RowsAffected()
			log.Printf("[INFO] Successfully updated target URL %s with %s = true (Rows affected: %d)", url, updateField, rowsAffected)
		}
	}

	// Update scan status to indicate SSL scan is complete but tech scan is pending
	UpdateMetaDataScanStatus(
		scanID,
		"running",
		string(output),
		stderr.String(),
		cmd.String(),
		time.Since(startTime).String(),
	)

	// Clean up the output file
	exec.Command("docker", "exec", "ars0n-framework-v2-nuclei-1", "rm", "/output.json").Run()

	log.Printf("[INFO] SSL scan completed for scan ID: %s, starting tech scan", scanID)

	// Run the HTTP/technologies scan
	if err := ExecuteAndParseNucleiTechScan(urls, scopeTargetID); err != nil {
		log.Printf("[ERROR] Failed to run HTTP/technologies scan: %v", err)
		UpdateMetaDataScanStatus(scanID, "error", string(output), fmt.Sprintf("Tech scan failed: %v", err), cmd.String(), time.Since(startTime).String())
		return
	}

	// Update final scan status after both scans complete successfully
	UpdateMetaDataScanStatus(
		scanID,
		"success",
		string(output),
		stderr.String(),
		cmd.String(),
		time.Since(startTime).String(),
	)

	log.Printf("[INFO] Both SSL and tech scans completed successfully for scan ID: %s", scanID)
}

func ExecuteAndParseNucleiTechScan(urls []string, scopeTargetID string) error {
	log.Printf("[INFO] Starting Nuclei HTTP/technologies scan")
	startTime := time.Now()

	// Create an HTTP client with reasonable timeouts and TLS config
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
		},
	}

	// Create a temporary file for URLs
	tempFile, err := os.CreateTemp("", "urls-*.txt")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	// Write URLs to temp file
	if err := os.WriteFile(tempFile.Name(), []byte(strings.Join(urls, "\n")), 0644); err != nil {
		return fmt.Errorf("failed to write URLs to temp file: %v", err)
	}

	// Copy the URLs file into the container
	copyCmd := exec.Command(
		"docker", "cp",
		tempFile.Name(),
		"ars0n-framework-v2-nuclei-1:/urls.txt",
	)
	if err := copyCmd.Run(); err != nil {
		return fmt.Errorf("failed to copy URLs file to container: %v", err)
	}

	// Run HTTP/technologies templates
	cmd := exec.Command(
		"docker", "exec", "ars0n-framework-v2-nuclei-1",
		"nuclei",
		"-t", "/root/nuclei-templates/http/technologies/",
		"-list", "/urls.txt",
		"-j",
		"-o", "/tech-output.json",
	)
	log.Printf("[INFO] Executing command: %s", cmd.String())

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("nuclei tech scan failed: %v\nstderr: %s", err, stderr.String())
	}

	// Read the JSON output file
	outputCmd := exec.Command(
		"docker", "exec", "ars0n-framework-v2-nuclei-1",
		"cat", "/tech-output.json",
	)
	output, err := outputCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to read output file: %v", err)
	}

	// Process findings and update the database
	findings := strings.Split(string(output), "\n")
	urlFindings := make(map[string][]interface{})

	for _, finding := range findings {
		if finding == "" {
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal([]byte(finding), &result); err != nil {
			log.Printf("[ERROR] Failed to parse JSON finding: %v", err)
			continue
		}

		matchedURL, ok := result["matched-at"].(string)
		if !ok {
			continue
		}

		// Convert matched-at to proper URL
		if strings.Contains(matchedURL, "://") {
			// Already a full URL
			matchedURL = NormalizeURL(matchedURL)
		} else if strings.Contains(matchedURL, ":") {
			// hostname:port format
			host := strings.Split(matchedURL, ":")[0]
			matchedURL = NormalizeURL("https://" + host)
		} else {
			// Just a hostname
			matchedURL = NormalizeURL("https://" + matchedURL)
		}

		// Add finding to the URL's findings array
		urlFindings[matchedURL] = append(urlFindings[matchedURL], result)
	}

	// Make HTTP requests and update each URL with its findings and response data
	for urlStr, findings := range urlFindings {
		// Parse URL to get hostname for DNS lookups
		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			log.Printf("[ERROR] Failed to parse URL %s: %v", urlStr, err)
			continue
		}

		// Perform DNS lookups
		dnsResults := PerformDNSLookups(parsedURL.Hostname())

		// Make HTTP request
		req, err := http.NewRequest("GET", urlStr, nil)
		if err != nil {
			log.Printf("[ERROR] Failed to create request for URL %s: %v", urlStr, err)
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[ERROR] Failed to make request to URL %s: %v", urlStr, err)
			continue
		}

		// Read response body
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("[ERROR] Failed to read response body from URL %s: %v", urlStr, err)
			continue
		}

		// Sanitize the response body
		sanitizedBody := SanitizeResponse(body)

		// Convert headers to map for JSON storage
		headers := make(map[string]interface{})
		for k, v := range resp.Header {
			if len(v) == 1 {
				headers[k] = SanitizeResponse([]byte(v[0]))
			} else {
				sanitizedValues := make([]string, len(v))
				for i, val := range v {
					sanitizedValues[i] = SanitizeResponse([]byte(val))
				}
				headers[k] = sanitizedValues
			}
		}

		// Update database with findings, response data, and DNS records
		query := `
			UPDATE target_urls 
			SET 
				findings_json = $1::jsonb,
				http_response = $2,
				http_response_headers = $3,
				dns_a_records = $4,
				dns_aaaa_records = $5,
				dns_cname_records = $6,
				dns_mx_records = $7,
				dns_txt_records = $8,
				dns_ns_records = $9,
				dns_ptr_records = $10,
				dns_srv_records = $11
			WHERE url = $12 AND scope_target_id = $13`

		// Convert findings to proper JSON
		findingsJSON, err := json.Marshal(findings)
		if err != nil {
			log.Printf("[ERROR] Failed to marshal findings for URL %s: %v", urlStr, err)
			continue
		}

		commandTag, err := dbPool.Exec(context.Background(),
			query,
			findingsJSON,
			sanitizedBody,
			headers,
			dnsResults.ARecords,
			dnsResults.AAAARecords,
			dnsResults.CNAMERecords,
			dnsResults.MXRecords,
			dnsResults.TXTRecords,
			dnsResults.NSRecords,
			dnsResults.PTRRecords,
			dnsResults.SRVRecords,
			urlStr,
			scopeTargetID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to update findings and response data for URL %s: %v", urlStr, err)
			continue
		}
		rowsAffected := commandTag.RowsAffected()
		log.Printf("[INFO] Updated findings and response data for URL %s (Rows affected: %d)", urlStr, rowsAffected)
	}

	// Clean up the output file
	exec.Command("docker", "exec", "ars0n-framework-v2-nuclei-1", "rm", "/tech-output.json").Run()

	log.Printf("[INFO] HTTP/technologies scan completed in %s", time.Since(startTime))
	return nil
}

func PerformDNSLookups(hostname string) DNSResults {
	var results DNSResults

	// Perform A record lookup
	if ips, err := net.LookupIP(hostname); err == nil {
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				results.ARecords = append(results.ARecords, ipv4.String())
			} else {
				results.AAAARecords = append(results.AAAARecords, ip.String())
			}
		}
	}

	// Perform CNAME lookup using a more reliable method
	if _, err := net.DefaultResolver.LookupHost(context.Background(), hostname); err == nil {
		// First try to get the CNAME record
		if cname, err := net.DefaultResolver.LookupCNAME(context.Background(), hostname); err == nil && cname != "" {
			cname = strings.TrimSuffix(cname, ".")
			if cname != hostname && !strings.HasSuffix(hostname, cname) {
				results.CNAMERecords = append(results.CNAMERecords, fmt.Sprintf("%s -> %s", cname, hostname))
			}
		}
	}

	// Perform MX lookup
	if mxRecords, err := net.LookupMX(hostname); err == nil {
		for _, mx := range mxRecords {
			results.MXRecords = append(results.MXRecords, fmt.Sprintf("%s %d", strings.TrimSuffix(mx.Host, "."), mx.Pref))
		}
	}

	// Perform TXT lookup
	if txtRecords, err := net.LookupTXT(hostname); err == nil {
		results.TXTRecords = append(results.TXTRecords, txtRecords...)
	}

	// Perform NS lookup
	if nsRecords, err := net.LookupNS(hostname); err == nil {
		for _, ns := range nsRecords {
			results.NSRecords = append(results.NSRecords, strings.TrimSuffix(ns.Host, "."))
		}
	}

	// Perform PTR lookup (reverse DNS)
	if names, err := net.LookupAddr(hostname); err == nil {
		for _, name := range names {
			results.PTRRecords = append(results.PTRRecords, strings.TrimSuffix(name, "."))
		}
	}

	// Perform SRV lookup for common services
	services := []string{"_http._tcp", "_https._tcp", "_ldap._tcp", "_kerberos._tcp"}
	for _, service := range services {
		if _, addrs, err := net.LookupSRV("", "", service+"."+hostname); err == nil {
			for _, addr := range addrs {
				results.SRVRecords = append(results.SRVRecords,
					fmt.Sprintf("%s.%s:%d %d %d",
						service, hostname, addr.Port, addr.Priority, addr.Weight))
			}
		}
	}

	return results
}

func UpdateMetaDataScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating Nuclei SSL scan status for %s to %s", scanID, status)
	query := `UPDATE metadata_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update Nuclei SSL scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated Nuclei SSL scan status for %s", scanID)
	}
}

func GetMetaDataScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var scan MetaDataStatus
	query := `SELECT * FROM metadata_scans WHERE scan_id = $1`
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

func GetMetaDataScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	query := `SELECT * FROM metadata_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan MetaDataStatus
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

func GanitizeResponse(input []byte) string {
	// Remove null bytes
	sanitized := bytes.ReplaceAll(input, []byte{0}, []byte{})

	// Convert to string and handle any invalid UTF-8
	str := string(sanitized)

	// Replace any other problematic characters
	str = strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return -1 // Drop the character
		}
		return r
	}, str)

	return str
}
