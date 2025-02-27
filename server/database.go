package main

import (
	"context"
	"log"
	"strings"
)

func createTables() {
	queries := []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto;`,
		`DROP TABLE IF EXISTS requests CASCADE;`,
		`CREATE TABLE IF NOT EXISTS scope_targets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			type VARCHAR(50) NOT NULL,
			mode VARCHAR(50) NOT NULL,
			scope_target TEXT NOT NULL,
			active BOOLEAN DEFAULT false,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS amass_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE, 
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
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
		`CREATE TABLE IF NOT EXISTS cloud_domains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			domain TEXT NOT NULL,
			type TEXT NOT NULL CHECK (type IN ('aws', 'gcp', 'azu')),
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_scans(scan_id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS asns (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			number TEXT NOT NULL,
			raw_data TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS subnets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			cidr TEXT NOT NULL,
			raw_data TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,
		`CREATE TABLE IF NOT EXISTS service_providers (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			provider TEXT NOT NULL,
			raw_data TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_scans(scan_id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS httpx_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE, 
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS gau_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE, 
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS sublist3r_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS assetfinder_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS ctl_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS subfinder_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS consolidated_subdomains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			subdomain TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id, subdomain)
		);`,
		`CREATE TABLE IF NOT EXISTS shuffledns_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS cewl_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			url TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS shufflednscustom_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS gospider_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS subdomainizer_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS nuclei_screenshots (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS metadata_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS target_urls (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			url TEXT NOT NULL UNIQUE,
			screenshot TEXT,
			status_code INTEGER,
			title TEXT,
			web_server TEXT,
			technologies TEXT[],
			content_length INTEGER,
			newly_discovered BOOLEAN DEFAULT false,
			no_longer_live BOOLEAN DEFAULT false,
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			has_deprecated_tls BOOLEAN DEFAULT false,
			has_expired_ssl BOOLEAN DEFAULT false,
			has_mismatched_ssl BOOLEAN DEFAULT false,
			has_revoked_ssl BOOLEAN DEFAULT false,
			has_self_signed_ssl BOOLEAN DEFAULT false,
			has_untrusted_root_ssl BOOLEAN DEFAULT false,
			has_wildcard_tls BOOLEAN DEFAULT false,
			findings_json JSONB,
			http_response TEXT,
			http_response_headers JSONB,
			dns_a_records TEXT[],
			dns_aaaa_records TEXT[],
			dns_cname_records TEXT[],
			dns_mx_records TEXT[],
			dns_txt_records TEXT[],
			dns_ns_records TEXT[],
			dns_ptr_records TEXT[],
			dns_srv_records TEXT[],
			katana_results JSONB,
			ffuf_results JSONB
		);`,
		`CREATE INDEX IF NOT EXISTS target_urls_url_idx ON target_urls (url);`,
		`CREATE INDEX IF NOT EXISTS target_urls_scope_target_id_idx ON target_urls (scope_target_id);`,

		// Add migration queries for new columns
		`DO $$ 
		BEGIN 
			BEGIN
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS http_response TEXT;
			EXCEPTION WHEN duplicate_column THEN 
				RAISE NOTICE 'Column http_response already exists in target_urls.';
			END;
		END $$;`,

		`DO $$ 
		BEGIN 
			BEGIN
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS http_response_headers JSONB;
			EXCEPTION WHEN duplicate_column THEN 
				RAISE NOTICE 'Column http_response_headers already exists in target_urls.';
			END;
		END $$;`,

		// Add migration queries for new DNS columns
		`DO $$ 
		BEGIN 
			BEGIN
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_a_records TEXT[];
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_aaaa_records TEXT[];
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_cname_records TEXT[];
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_mx_records TEXT[];
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_txt_records TEXT[];
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_ns_records TEXT[];
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_ptr_records TEXT[];
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS dns_srv_records TEXT[];
			EXCEPTION WHEN duplicate_column THEN 
				RAISE NOTICE 'DNS columns already exist in target_urls.';
			END;
		END $$;`,

		`DO $$ 
		BEGIN 
			BEGIN
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS katana_results JSONB;
			EXCEPTION WHEN duplicate_column THEN 
				RAISE NOTICE 'Column katana_results already exists in target_urls.';
			END;
		END $$;`,

		`DO $$ 
		BEGIN 
			BEGIN
				ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS ffuf_results JSONB;
			EXCEPTION WHEN duplicate_column THEN 
				RAISE NOTICE 'Column ffuf_results already exists in target_urls.';
			END;
		END $$;`,
	}

	for _, query := range queries {
		_, err := dbPool.Exec(context.Background(), query)
		if err != nil {
			log.Printf("[ERROR] Failed to execute query: %s, error: %v", query, err)
			// Don't fatally exit on migration errors
			if !strings.Contains(query, "ALTER TABLE") {
				log.Fatalf("[ERROR] Failed to execute query: %s, error: %v", query, err)
			}
		}
	}

	deletePendingScansQuery := `DELETE FROM amass_scans WHERE status = 'pending';`
	_, err := dbPool.Exec(context.Background(), deletePendingScansQuery)
	if err != nil {
		log.Fatalf("[ERROR] Failed to delete pending Amass scans: %v", err)
	}
	log.Println("[INFO] Deleted any Amass scans with status 'pending'")
}
