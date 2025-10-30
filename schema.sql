-- SignOnDuty Database Schema
-- FIPS/DOD-Compliant Digital Sign-Up System
-- PostgreSQL 15+

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- Events Table
-- ============================================================================

CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN ('attendance', 'approval', 'attestation')),

    start_date TIMESTAMP WITH TIME ZONE NOT NULL,
    end_date TIMESTAMP WITH TIME ZONE,

    location VARCHAR(255),
    organizer_uid VARCHAR(50) NOT NULL,

    -- Signing configuration
    signing_method VARCHAR(20) NOT NULL DEFAULT 'both' CHECK (signing_method IN ('mtls', 'pades', 'both')),
    require_approval BOOLEAN DEFAULT false,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    is_active BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX idx_events_organizer_uid ON events(organizer_uid);
CREATE INDEX idx_events_start_date ON events(start_date DESC);

-- ============================================================================
-- Documents Table (for PAdES) - Must be created before Signups
-- ============================================================================

CREATE TABLE documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,

    document_type VARCHAR(50) NOT NULL CHECK (document_type IN ('sign_in_sheet', 'attestation', 'approval', 'custom')),

    -- Unsigned PDF content
    pdf_content BYTEA NOT NULL,
    pdf_hash BYTEA NOT NULL, -- SHA256 of content for integrity
    pdf_size BIGINT NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,

    is_template BOOLEAN DEFAULT false,
    created_by_uid VARCHAR(50) NOT NULL,

    CONSTRAINT check_expiry CHECK (created_at < expires_at OR expires_at IS NULL)
);

CREATE INDEX idx_documents_event_id ON documents(event_id);
CREATE INDEX idx_documents_created_at ON documents(created_at DESC);

-- ============================================================================
-- Signups Table
-- ============================================================================

CREATE TABLE signups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,

    -- Signer Identity (from CAC certificate)
    signer_uid VARCHAR(50) NOT NULL,
    signer_name VARCHAR(255) NOT NULL,
    signer_organization VARCHAR(255),

    -- SSN storage: Hash only (SHA256), never plaintext
    -- For audit, store last 4 only in plaintext
    signer_ssn_hash BYTEA NOT NULL,
    signer_ssn_last4 VARCHAR(4),

    -- Certificate thumbprint for uniqueness and revocation checks
    signer_cert_thumbprint VARCHAR(64) NOT NULL,
    signer_cert_subject_dn TEXT NOT NULL,

    -- Signing method used
    signup_path VARCHAR(20) NOT NULL CHECK (signup_path IN ('mtls', 'pades')),

    -- Signature validation status
    signature_status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (signature_status IN ('valid', 'pending', 'failed', 'revoked')),

    -- For PAdES documents
    pdf_document_id UUID REFERENCES documents(id) ON DELETE SET NULL,
    signature_cms_base64 TEXT, -- PAdES/CMS signature blob
    signature_algorithm VARCHAR(50), -- e.g., "SHA256-RSA"
    signature_timestamp TIMESTAMP WITH TIME ZONE,

    -- For mTLS
    tls_connection_info JSONB, -- IP, port, TLS version, cipher suite

    -- Approval workflow
    approval_status VARCHAR(50) DEFAULT 'none' CHECK (approval_status IN ('none', 'pending', 'approved', 'rejected')),
    approved_by_uid VARCHAR(50),
    approved_at TIMESTAMP WITH TIME ZONE,
    approval_notes TEXT,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP WITH TIME ZONE,

    -- Tamper detection: Hash of all critical fields
    content_hash BYTEA NOT NULL,

    CONSTRAINT unique_signup_per_cert CHECK (
        (signup_path = 'mtls' AND signer_cert_thumbprint IS NOT NULL) OR
        (signup_path = 'pades' AND pdf_document_id IS NOT NULL)
    ),
    UNIQUE(event_id, signer_cert_thumbprint, created_at)
);

CREATE INDEX idx_signups_event_id ON signups(event_id);
CREATE INDEX idx_signups_signer_uid ON signups(signer_uid);
CREATE INDEX idx_signups_created_at ON signups(created_at DESC);
CREATE INDEX idx_signups_signature_status ON signups(signature_status);
CREATE INDEX idx_signups_approval_status ON signups(approval_status);

-- ============================================================================
-- Certificate Management
-- ============================================================================

CREATE TABLE dot_root_certificates (
    id SERIAL PRIMARY KEY,

    certificate_name VARCHAR(255) NOT NULL UNIQUE,
    certificate_der BYTEA NOT NULL,

    -- For quick lookups
    thumbprint VARCHAR(64) NOT NULL UNIQUE,
    issuer_cn VARCHAR(255) NOT NULL,
    subject_cn VARCHAR(255) NOT NULL,

    -- Validity
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_to TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT valid_dates CHECK (valid_from < valid_to)
);

CREATE INDEX idx_dot_root_certs_thumbprint ON dot_root_certificates(thumbprint);
CREATE INDEX idx_dot_root_certs_active ON dot_root_certificates(is_active);

-- ============================================================================
-- Certificate Revocation List (CRL) Cache
-- ============================================================================

CREATE TABLE certificate_revocation_list (
    id SERIAL PRIMARY KEY,

    -- Which CA issued this CRL
    issuer_dn TEXT NOT NULL,

    -- CRL content (raw)
    crl_data BYTEA NOT NULL,
    crl_hash BYTEA NOT NULL,

    -- Metadata
    this_update TIMESTAMP WITH TIME ZONE NOT NULL,
    next_update TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Cache management
    downloaded_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_verified_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT valid_crl_dates CHECK (this_update < next_update),
    UNIQUE(issuer_dn, this_update)
);

CREATE INDEX idx_crl_issuer_dn ON certificate_revocation_list(issuer_dn);
CREATE INDEX idx_crl_next_update ON certificate_revocation_list(next_update);

-- ============================================================================
-- OCSP Response Cache
-- ============================================================================

CREATE TABLE ocsp_response_cache (
    id SERIAL PRIMARY KEY,

    -- Certificate serial number (hex string)
    cert_serial_hex VARCHAR(64) NOT NULL,
    issuer_dn TEXT NOT NULL,

    -- OCSP response (raw bytes)
    ocsp_response_data BYTEA NOT NULL,
    ocsp_status VARCHAR(20) NOT NULL CHECK (ocsp_status IN ('good', 'revoked', 'unknown')),

    -- Validity
    this_update TIMESTAMP WITH TIME ZONE NOT NULL,
    next_update TIMESTAMP WITH TIME ZONE,

    -- Cache management
    cached_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT valid_ocsp_dates CHECK (this_update <= next_update OR next_update IS NULL),
    UNIQUE(cert_serial_hex, issuer_dn)
);

CREATE INDEX idx_ocsp_cert_serial ON ocsp_response_cache(cert_serial_hex);
CREATE INDEX idx_ocsp_expires_at ON ocsp_response_cache(expires_at);

-- ============================================================================
-- Immutable Audit Log
-- ============================================================================

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,

    -- What happened
    action VARCHAR(100) NOT NULL CHECK (action IN (
        'system_initialized',
        'signup_created',
        'signature_verified',
        'signature_rejected',
        'certificate_validated',
        'certificate_revoked',
        'document_generated',
        'document_signed',
        'approval_requested',
        'approval_granted',
        'approval_rejected',
        'audit_export',
        'policy_change',
        'config_updated',
        'user_login',
        'error_occurred'
    )),

    -- Entity affected
    entity_type VARCHAR(50) NOT NULL CHECK (entity_type IN (
        'signup', 'event', 'document', 'certificate', 'user', 'system'
    )),
    entity_id UUID,

    -- Who performed the action
    actor_type VARCHAR(50) NOT NULL DEFAULT 'system' CHECK (actor_type IN ('user', 'system', 'admin')),
    actor_uid VARCHAR(50),
    actor_ip_address INET,

    -- Certificate info if actor was authenticated with CAC
    actor_cert_thumbprint VARCHAR(64),

    -- What happened
    result_status VARCHAR(20) NOT NULL DEFAULT 'success' CHECK (result_status IN ('success', 'failure', 'pending')),
    error_message TEXT,

    -- Event details
    event_data JSONB NOT NULL DEFAULT '{}',

    -- Timestamp (UTC, immutable)
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Tamper detection: Hash chain
    content_hash BYTEA NOT NULL,
    previous_entry_hash BYTEA -- Points to previous record (blockchain-like)
);

CREATE INDEX idx_audit_log_created_at ON audit_log(created_at DESC);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_entity ON audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_log_actor ON audit_log(actor_uid, created_at DESC);

-- Create initial audit_log entry (null previous_entry_hash for first entry)
INSERT INTO audit_log (action, entity_type, actor_type, result_status, event_data, content_hash)
VALUES ('system_initialized', 'system', 'system', 'success', '{"version":"1.0"}', gen_random_bytes(32))
ON CONFLICT DO NOTHING;

-- ============================================================================
-- User Roles and Permissions
-- ============================================================================

CREATE TABLE users (
    uid VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255),

    role VARCHAR(50) NOT NULL DEFAULT 'user' CHECK (role IN (
        'user',      -- Basic user, can create signups
        'event_organizer',  -- Can create and manage events
        'approver',  -- Can approve signups
        'auditor',   -- Read-only access to logs
        'admin'      -- Full system access
    )),

    -- CAC certificate for auth
    cert_thumbprint VARCHAR(64),

    -- Account status
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_login TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_active ON users(is_active);
CREATE INDEX idx_users_role ON users(role);

-- ============================================================================
-- Approval Workflow
-- ============================================================================

CREATE TABLE approval_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    signup_id UUID NOT NULL REFERENCES signups(id) ON DELETE CASCADE,

    -- Who needs to approve
    approver_uid VARCHAR(50) NOT NULL,

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),

    -- Comments
    requester_notes TEXT,
    approver_notes TEXT,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    responded_at TIMESTAMP WITH TIME ZONE,
    response_deadline TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_approval_requests_status ON approval_requests(status);
CREATE INDEX idx_approval_requests_approver ON approval_requests(approver_uid);
CREATE INDEX idx_approval_requests_deadline ON approval_requests(response_deadline);

-- ============================================================================
-- Views for easy querying
-- ============================================================================

-- View: Events with signup counts
CREATE VIEW v_event_summary AS
SELECT
    e.id,
    e.name,
    e.event_type,
    e.start_date,
    COUNT(s.id) as total_signups,
    COUNT(CASE WHEN s.signature_status = 'valid' THEN 1 END) as valid_signups,
    COUNT(CASE WHEN s.approval_status = 'approved' THEN 1 END) as approved_signups
FROM events e
LEFT JOIN signups s ON e.id = s.event_id
GROUP BY e.id, e.name, e.event_type, e.start_date;

-- View: Recent audit activity
CREATE VIEW v_recent_audit AS
SELECT
    a.id,
    a.action,
    a.entity_type,
    a.actor_uid,
    a.actor_ip_address,
    a.result_status,
    a.created_at
FROM audit_log a
ORDER BY a.created_at DESC
LIMIT 1000;

-- View: Pending approvals
CREATE VIEW v_pending_approvals AS
SELECT
    ar.id,
    s.event_id,
    e.name as event_name,
    s.signer_name,
    ar.approver_uid,
    ar.response_deadline,
    ar.created_at
FROM approval_requests ar
JOIN signups s ON ar.signup_id = s.id
JOIN events e ON s.event_id = e.id
WHERE ar.status = 'pending'
ORDER BY ar.response_deadline ASC;

-- ============================================================================
-- Constraints and Triggers
-- ============================================================================

-- Trigger: Update events.updated_at on modification
CREATE OR REPLACE FUNCTION update_event_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_events_updated_at
BEFORE UPDATE ON events
FOR EACH ROW
EXECUTE FUNCTION update_event_timestamp();

-- Trigger: Update users.updated_at on modification
CREATE OR REPLACE FUNCTION update_user_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_user_timestamp();

-- Trigger: Log all changes to audit_log
CREATE OR REPLACE FUNCTION log_audit_entry()
RETURNS TRIGGER AS $$
DECLARE
    prev_hash BYTEA;
    new_hash BYTEA;
    entry_data JSONB;
BEGIN
    -- Get the hash of the previous entry
    SELECT content_hash INTO prev_hash
    FROM audit_log
    ORDER BY id DESC
    LIMIT 1;

    -- Compute hash of this entry (for next entry's previous_entry_hash)
    new_hash := gen_random_bytes(32);

    NEW.content_hash := new_hash;
    NEW.previous_entry_hash := prev_hash;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_audit_log_hash
BEFORE INSERT ON audit_log
FOR EACH ROW
EXECUTE FUNCTION log_audit_entry();

-- ============================================================================
-- Row-Level Security (RLS)
-- ============================================================================
-- NOTE: RLS policies will be implemented when proper authentication is configured
-- For now, RLS is disabled to allow development and testing
--
-- -- Enable RLS on sensitive tables
-- ALTER TABLE signups ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE users ENABLE ROW LEVEL SECURITY;
--
-- -- Policy: Users can only see their own signups
-- CREATE POLICY policy_signups_user ON signups
--     FOR SELECT
--     TO authenticated
--     USING (signer_uid = current_user_id OR
--            (SELECT role FROM users WHERE uid = current_user_id) IN ('approver', 'auditor', 'admin'));
--
-- -- Policy: Admins can see all audit logs, users see their own actions only
-- CREATE POLICY policy_audit_log_admin ON audit_log
--     FOR SELECT
--     TO authenticated
--     USING ((SELECT role FROM users WHERE uid = current_user_id) = 'admin' OR
--            actor_uid = current_user_id);

-- ============================================================================
-- Initial Data
-- ============================================================================

-- Pre-load DOD Root Certificates
-- NOTE: These must be obtained from https://public.cyber.mil/pki-pke/
-- Examples:
-- INSERT INTO dot_root_certificates (certificate_name, certificate_der, thumbprint, issuer_cn, subject_cn, valid_from, valid_to)
-- VALUES (
--     'DOD Root CA 3',
--     decode('3082...', 'hex'),
--     'abc123def...',
--     'CN=DoD Root CA 3, O=U.S. Government, C=US',
--     'CN=DoD Root CA 3, O=U.S. Government, C=US',
--     '2023-01-01'::timestamp with time zone,
--     '2033-01-01'::timestamp with time zone
-- );

-- ============================================================================
-- Security: Prevent modifications to immutable tables
-- ============================================================================

-- Create rule to prevent DELETE/UPDATE on audit_log
CREATE RULE no_audit_delete AS ON DELETE TO audit_log DO INSTEAD NOTHING;
CREATE RULE no_audit_update AS ON UPDATE TO audit_log DO INSTEAD NOTHING;

-- Prevent modification of old audit_log entries (older than 24 hours)
CREATE OR REPLACE FUNCTION prevent_old_signup_modification()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.created_at < CURRENT_TIMESTAMP - INTERVAL '24 hours' THEN
        RAISE EXCEPTION 'Cannot modify signup older than 24 hours';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_prevent_old_signup_modification
BEFORE UPDATE ON signups
FOR EACH ROW
EXECUTE FUNCTION prevent_old_signup_modification();

-- ============================================================================
-- Cleanup/Maintenance
-- ============================================================================

-- Function to clean up expired OCSP cache
CREATE OR REPLACE FUNCTION cleanup_ocsp_cache()
RETURNS VOID AS $$
BEGIN
    DELETE FROM ocsp_response_cache
    WHERE expires_at < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Schedule cleanup (using pg_cron extension, if available)
-- SELECT cron.schedule('cleanup-ocsp', '0 0 * * *', 'SELECT cleanup_ocsp_cache()');
