package main

import (
	"database/sql"
	"time"
)

type ASN struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Number    string    `json:"number"`
	RawData   string    `json:"raw_data"`
	CreatedAt time.Time `json:"created_at"`
}

type Subnet struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	CIDR      string    `json:"cidr"`
	RawData   string    `json:"raw_data"`
	CreatedAt time.Time `json:"created_at"`
}

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

type CloudDomain struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

type RequestPayload struct {
	Type        string `json:"type"`
	Mode        string `json:"mode"`
	ScopeTarget string `json:"scope_target"`
	Active      bool   `json:"active"`
}

type ResponsePayload struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Mode        string `json:"mode"`
	ScopeTarget string `json:"scope_target"`
	Active      bool   `json:"active"`
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

type ServiceProvider struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Provider  string    `json:"provider"`
	RawData   string    `json:"raw_data"`
	CreatedAt time.Time `json:"created_at"`
}

type HttpxScanStatus struct {
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

type ScanSummary struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Domain    string    `json:"domain"`
	Status    string    `json:"status"`
	Result    string    `json:"result,omitempty"`
	Error     string    `json:"error,omitempty"`
	StdOut    string    `json:"stdout,omitempty"`
	StdErr    string    `json:"stderr,omitempty"`
	Command   string    `json:"command,omitempty"`
	ExecTime  string    `json:"execution_time,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ScanType  string    `json:"scan_type"`
}

type GauScanStatus struct {
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

type Sublist3rScanStatus struct {
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

type AssetfinderScanStatus struct {
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

type CTLScanStatus struct {
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

type SubfinderScanStatus struct {
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

type ShuffleDNSScanStatus struct {
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

type CeWLScanStatus struct {
	ID            string         `json:"id"`
	ScanID        string         `json:"scan_id"`
	URL           string         `json:"url"`
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

type GoSpiderScanStatus struct {
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

type SubdomainizerScanStatus struct {
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

type NucleiScreenshotStatus struct {
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

type NucleiSSLStatus struct {
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

type TargetURL struct {
	ID                  string                 `json:"id"`
	URL                 string                 `json:"url"`
	Screenshot          sql.NullString         `json:"screenshot,omitempty"`
	StatusCode          int                    `json:"status_code"`
	Title               sql.NullString         `json:"title,omitempty"`
	WebServer           sql.NullString         `json:"web_server,omitempty"`
	Technologies        []string               `json:"technologies"`
	ContentLength       int                    `json:"content_length"`
	NewlyDiscovered     bool                   `json:"newly_discovered"`
	NoLongerLive        bool                   `json:"no_longer_live"`
	ScopeTargetID       string                 `json:"scope_target_id"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
	HasDeprecatedTLS    bool                   `json:"has_deprecated_tls"`
	HasExpiredSSL       bool                   `json:"has_expired_ssl"`
	HasMismatchedSSL    bool                   `json:"has_mismatched_ssl"`
	HasRevokedSSL       bool                   `json:"has_revoked_ssl"`
	HasSelfSignedSSL    bool                   `json:"has_self_signed_ssl"`
	HasUntrustedRootSSL bool                   `json:"has_untrusted_root_ssl"`
	HasWildcardTLS      bool                   `json:"has_wildcard_tls"`
	FindingsJSON        []interface{}          `json:"findings_json"`
	HTTPResponse        sql.NullString         `json:"http_response,omitempty"`
	HTTPResponseHeaders map[string]interface{} `json:"http_response_headers,omitempty"`
}

type ASNResponse struct {
	Number  string `json:"number"`
	RawData string `json:"raw_data"`
}

type SubnetResponse struct {
	CIDR    string `json:"cidr"`
	RawData string `json:"raw_data"`
}

type ServiceProviderResponse struct {
	Provider string `json:"provider"`
	RawData  string `json:"raw_data"`
}

type CertEntry struct {
	NameValue string `json:"name_value"`
}

type TargetURLResponse struct {
	ID                  string                 `json:"id"`
	URL                 string                 `json:"url"`
	Screenshot          string                 `json:"screenshot,omitempty"`
	StatusCode          int                    `json:"status_code"`
	Title               string                 `json:"title,omitempty"`
	WebServer           string                 `json:"web_server,omitempty"`
	Technologies        []string               `json:"technologies"`
	ContentLength       int                    `json:"content_length"`
	NewlyDiscovered     bool                   `json:"newly_discovered"`
	NoLongerLive        bool                   `json:"no_longer_live"`
	ScopeTargetID       string                 `json:"scope_target_id"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
	HasDeprecatedTLS    bool                   `json:"has_deprecated_tls"`
	HasExpiredSSL       bool                   `json:"has_expired_ssl"`
	HasMismatchedSSL    bool                   `json:"has_mismatched_ssl"`
	HasRevokedSSL       bool                   `json:"has_revoked_ssl"`
	HasSelfSignedSSL    bool                   `json:"has_self_signed_ssl"`
	HasUntrustedRootSSL bool                   `json:"has_untrusted_root_ssl"`
	HasWildcardTLS      bool                   `json:"has_wildcard_tls"`
	FindingsJSON        []interface{}          `json:"findings_json"`
	HTTPResponse        string                 `json:"http_response,omitempty"`
	HTTPResponseHeaders map[string]interface{} `json:"http_response_headers,omitempty"`
}
