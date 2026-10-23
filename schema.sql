CREATE DATABASE IF NOT EXISTS cloudsentinel
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE cloudsentinel;

CREATE TABLE IF NOT EXISTS users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(80) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin', 'analyst') NOT NULL DEFAULT 'analyst',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_username (username),
  KEY idx_users_role_active (role, is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS incidents (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  title VARCHAR(180) NOT NULL,
  description TEXT NOT NULL,
  category VARCHAR(80) NOT NULL,
  severity ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL DEFAULT 'Medium',
  status ENUM('Open', 'In Progress', 'Resolved', 'Closed') NOT NULL DEFAULT 'Open',
  reporter_id INT UNSIGNED NOT NULL,
  assigned_to INT UNSIGNED NULL,
  affected_resource VARCHAR(255) NULL,
  detection_at DATETIME NULL,
  resolution_notes TEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_incidents_status (status),
  KEY idx_incidents_severity (severity),
  KEY idx_incidents_category (category),
  KEY idx_incidents_assigned_to (assigned_to),
  KEY idx_incidents_updated_at (updated_at),
  CONSTRAINT fk_incidents_reporter FOREIGN KEY (reporter_id) REFERENCES users(id),
  CONSTRAINT fk_incidents_assignee FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id INT UNSIGNED NULL,
  action VARCHAR(80) NOT NULL,
  entity_type VARCHAR(40) NULL,
  entity_id BIGINT UNSIGNED NULL,
  details VARCHAR(1000) NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_audit_created_at (created_at),
  KEY idx_audit_entity (entity_type, entity_id),
  KEY idx_audit_user (user_id),
  CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS evidence (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  incident_id BIGINT UNSIGNED NOT NULL,
  original_name VARCHAR(255) NOT NULL,
  storage_key CHAR(32) NOT NULL,
  uploaded_by INT UNSIGNED NOT NULL,
  size_bytes BIGINT UNSIGNED NOT NULL,
  sha256 CHAR(64) NOT NULL,
  uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_evidence_storage_key (storage_key),
  KEY idx_evidence_incident (incident_id),
  CONSTRAINT fk_evidence_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
  CONSTRAINT fk_evidence_uploader FOREIGN KEY (uploaded_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vulnerabilities (
  cve_id VARCHAR(24) NOT NULL,
  source_name VARCHAR(40) NOT NULL,
  source_identifier VARCHAR(100) NOT NULL,
  source_url VARCHAR(500) NOT NULL,
  description TEXT NULL,
  published_at DATETIME NULL,
  modified_at DATETIME NULL,
  severity_score DECIMAL(4,1) NULL,
  severity_label VARCHAR(32) NULL,
  affected_products TEXT NULL,
  is_kev BOOLEAN NOT NULL DEFAULT FALSE,
  kev_source_name VARCHAR(40) NULL,
  kev_source_identifier VARCHAR(100) NULL,
  kev_source_url VARCHAR(500) NULL,
  kev_date_added DATE NULL,
  kev_due_date DATE NULL,
  kev_required_action TEXT NULL,
  kev_ransomware_use VARCHAR(80) NULL,
  imported_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (cve_id),
  KEY idx_vulnerabilities_published (published_at),
  KEY idx_vulnerabilities_severity (severity_label, severity_score),
  KEY idx_vulnerabilities_kev (is_kev, kev_date_added)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS attack_objects (
  stix_id VARCHAR(255) NOT NULL,
  external_id VARCHAR(80) NOT NULL,
  object_type ENUM('tactic', 'technique') NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT NULL,
  tactic_shortname VARCHAR(100) NULL,
  source_name VARCHAR(40) NOT NULL,
  source_identifier VARCHAR(255) NOT NULL,
  source_url VARCHAR(500) NOT NULL,
  published_at DATETIME NULL,
  modified_at DATETIME NULL,
  imported_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (stix_id),
  UNIQUE KEY uq_attack_external_id (external_id),
  KEY idx_attack_object_type (object_type, name),
  KEY idx_attack_modified_at (modified_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS network_observations (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  source_identifier CHAR(64) NOT NULL,
  dataset_name VARCHAR(80) NOT NULL,
  source_url VARCHAR(500) NOT NULL,
  attack_category VARCHAR(120) NOT NULL,
  observed_at DATETIME NULL,
  source_ip VARCHAR(45) NULL,
  destination_ip VARCHAR(45) NULL,
  protocol VARCHAR(32) NULL,
  flow_duration BIGINT UNSIGNED NULL,
  packets BIGINT UNSIGNED NULL,
  bytes BIGINT UNSIGNED NULL,
  imported_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_network_source_identifier (source_identifier),
  KEY idx_network_category_observed (attack_category, observed_at),
  KEY idx_network_imported_at (imported_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS source_sync_state (
  source_name VARCHAR(40) NOT NULL,
  last_success_at DATETIME NOT NULL,
  cursor_value VARCHAR(80) NULL,
  records_imported INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (source_name),
  KEY idx_source_sync_last_success (last_success_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create the least-privilege app account separately as documented in README.md.
-- Its host must match DB_HOST (127.0.0.1 by default); do not run the app as root.
