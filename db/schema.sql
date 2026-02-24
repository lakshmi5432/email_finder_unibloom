PRAGMA foreign_keys = ON;

-- Stores one final result per LinkedIn profile URL.
CREATE TABLE IF NOT EXISTS lookups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    linkedin_url TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('found', 'not_found', 'error')),
    email TEXT,
    full_name TEXT,
    company TEXT,
    job_title TEXT,
    provider TEXT,
    confidence REAL CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    hubspot_status TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Keeps updated_at in sync on any row update.
CREATE TRIGGER IF NOT EXISTS trg_lookups_set_updated_at
AFTER UPDATE ON lookups
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE lookups
    SET updated_at = CURRENT_TIMESTAMP
    WHERE id = OLD.id;
END;

CREATE INDEX IF NOT EXISTS idx_lookups_status ON lookups(status);
CREATE INDEX IF NOT EXISTS idx_lookups_provider ON lookups(provider);
CREATE INDEX IF NOT EXISTS idx_lookups_created_at ON lookups(created_at);

-- Stores each provider call attempt for traceability/debugging.
CREATE TABLE IF NOT EXISTS provider_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lookup_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    attempt_order INTEGER NOT NULL CHECK (attempt_order >= 1),
    result TEXT NOT NULL CHECK (result IN ('found', 'not_found', 'error')),
    http_status INTEGER CHECK (http_status IS NULL OR (http_status >= 100 AND http_status <= 599)),
    response_time_ms INTEGER CHECK (response_time_ms IS NULL OR response_time_ms >= 0),
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (lookup_id) REFERENCES lookups(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_provider_attempts_lookup_attempt
    ON provider_attempts(lookup_id, attempt_order);
CREATE INDEX IF NOT EXISTS idx_provider_attempts_lookup_id
    ON provider_attempts(lookup_id);
CREATE INDEX IF NOT EXISTS idx_provider_attempts_provider
    ON provider_attempts(provider);

-- Manual usage counters for free-tier credit management.
CREATE TABLE IF NOT EXISTS provider_usage (
    provider TEXT NOT NULL,
    month_key TEXT NOT NULL,
    used_count INTEGER NOT NULL DEFAULT 0 CHECK (used_count >= 0),
    estimated_limit INTEGER CHECK (estimated_limit IS NULL OR estimated_limit >= 0),
    is_enabled INTEGER NOT NULL DEFAULT 1 CHECK (is_enabled IN (0, 1)),
    PRIMARY KEY (provider, month_key),
    CHECK (
        month_key GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]'
        AND CAST(substr(month_key, 6, 2) AS INTEGER) BETWEEN 1 AND 12
    )
);
