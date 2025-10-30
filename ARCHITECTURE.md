# SignOnDuty: CAC-Authenticated Digital Sign-Up System

## Project Overview

**SignOnDuty** is a FIPS/DOD-compliant digital sign-up system that enables military and government personnel to authenticate and sign documents using their Common Access Card (CAC).

**Compliance Framework:**
- FIPS 140-3: Cryptographic Module Validation
- FIPS 201-3: Personal Identity Verification (PIV)
- NIST SP 800-73-5: PIV Interfaces
- NIST SP 800-78-5: Cryptographic Algorithms
- NIST SP 800-157: Derived PIV Credentials
- DOD 8570: Information Assurance Requirements
- NIST SP 800-115: Security Testing
- CJIS Security Policy: Biometric Information

## Architecture Overview

### Two-Path Authentication System

**Path 1: mTLS + Audit Trail (Simpler)**
- Client presents CAC certificate via mutual TLS
- Server validates certificate chain against DOD PKI roots
- Sign-up submission recorded with cryptographic audit trail
- Best for: Real-time sign-ups, attendance records, quick verification

**Path 2: PAdES/CMS Document Signing (Legal)**
- User downloads PDF document
- Signs locally in Acrobat/compatible software using CAC
- Submits signed PDF to server
- Server validates signature and extracts signer identity
- Best for: Formal documents, legal liability, non-repudiation

### Technology Stack

**Backend:**
- Language: Go 1.22+
- Framework: Echo (lightweight HTTP)
- Crypto: crypto/x509, crypto/sha256, crypto/rsa (FIPS-approved algorithms)
- PDF: github.com/pdfcpu/pdfcpu (PAdES signing support)
- Database: PostgreSQL 15+ with FIPS mode enabled
- TLS: TLS 1.3 minimum

**Frontend:**
- Framework: SvelteKit
- UI: TailwindCSS
- File Upload: dropzone.js
- PDF Tools: PDF.js for preview

**Infrastructure:**
- Cloud: AWS (with FedRAMP-Ready services)
  - EC2 or ECS for compute
  - RDS PostgreSQL (encrypted at rest with AWS KMS)
  - API Gateway (mTLS support)
  - CloudTrail for audit logs
  - AWS Certificate Manager for PKI integration
- Alternative: Azure Government Cloud (more directly FedRAMP)

---

## Detailed Technical Design

### 1. CAC Certificate Processing

**CAC Certificate Chain:**
```
DOD Root CA 3 / DOD Root CA 4 (Root)
  ↓
Issuing CA (Intermediate)
  ↓
Agency CA (Intermediate)
  ↓
CAC Certificate (End Entity)
  Subject: CN=LASTNAME.FIRSTNAME.SSN, OU=Issuing Organization
  Subject Alt Name: UPN=firstname.lastname@usmil.mil
```

**Validation Pipeline:**
1. Extract certificate from mTLS connection or signed PDF
2. Verify certificate chain against DOD root CAs (hardcoded/pinned)
3. Validate certificate dates (not before/after)
4. Extract cardholder identity: FIRSTNAME, LASTNAME, SSN, UID
5. Cross-reference against authorized personnel database (optional)
6. Log certificate presentation in audit trail

**Key Classes:**

```go
// Certificate subject as encoded in CAC
type CACIdentity struct {
    FirstName        string // From certificate CN
    LastName         string
    SSN              string // Last 4 digits stored, full in audit only
    Organization     string
    DistinguishedName string
    Thumbprint       string // SHA-256 cert hash
}

// Represents a validated CAC authentication event
type CACAuthentication struct {
    Identity          CACIdentity
    CertificateChain  []*x509.Certificate
    ValidationStatus  string // "valid", "expired", "untrusted_root", "revoked"
    Timestamp         time.Time
    TLSConnectionInfo string // IP, port, protocol version
}
```

### 2. mTLS Implementation (Path 1)

**Server Configuration:**
- TLS 1.3 minimum
- Require client certificate
- Validate against DOD PKI roots
- Extract subject DN and SANs
- Record all connection metadata

**Endpoint: `POST /api/v1/signups/mtls`**

```go
type MTLSSignUpRequest struct {
    EventName    string                 `json:"event_name" validate:"required"`
    EventDate    time.Time              `json:"event_date" validate:"required"`
    EventType    string                 `json:"event_type"` // "attendance", "approval", "attestation"
    CustomFields map[string]interface{} `json:"custom_fields"`
}

type SignUpResponse struct {
    SignUpID      string    `json:"signup_id"`
    Timestamp     time.Time `json:"timestamp"`
    SignerName    string    `json:"signer_name"`
    VerifyToken   string    `json:"verify_token"` // For client to verify authenticity
}
```

**Workflow:**
1. Client connects via mTLS (CAC certificate in client cert)
2. Server validates certificate chain
3. POST to `/api/v1/signups/mtls` with sign-up details
4. Server creates immutable audit record
5. Server returns SignUpID and cryptographic proof token

### 3. PAdES/CMS Implementation (Path 2)

**PDF Generation Endpoint: `POST /api/v1/signups/documents`**

```go
type DocumentRequest struct {
    EventName    string
    EventDate    time.Time
    Language     string // "en", "es"
    ReturnURL    string // For after-signing callback
}

type DocumentResponse struct {
    DocumentID  string `json:"document_id"`
    PDFBase64   string `json:"pdf_base64"`
    DocumentURL string `json:"document_url"` // S3 pre-signed URL
}
```

**Server-side PDF Creation:**
1. Generate unsigned PDF with event details
2. Add visible signature field
3. Return PDF to client

**Client-side Signing (User's System):**
1. User downloads PDF
2. Opens in Adobe Acrobat or equivalent
3. Right-click signature field → Sign with ID
4. Select CAC certificate
5. System prompts for CAC PIN
6. PDF is signed locally with PAdES-B-LTV profile

**Signature Verification Endpoint: `POST /api/v1/signups/verify-pdf`**

```go
type PDFVerificationRequest struct {
    DocumentID  string `json:"document_id"`
    PDFBase64   string `json:"pdf_base64"` // Or upload multipart/form-data
}

type SignatureValidation struct {
    Valid              bool
    SignedBy           CACIdentity
    SignatureTime      time.Time
    CertificateChain   []*x509.Certificate
    SignatureAlgorithm string
    Timestamp          time.Time `json:"timestamp"`
    SignUpID           string    `json:"signup_id"`
}
```

**Signature Validation Pipeline:**
1. Extract PDF and parse CMS signature structure
2. Locate X.509 certificate in signature container
3. Verify certificate chain against DOD roots
4. Validate signature mathematical correctness
5. Verify PDF content integrity (hasn't changed since signing)
6. Extract signer identity and timestamp
7. Create immutable audit record
8. Return SignUpID

---

## Database Schema

### Core Tables

**Table: `signups`**
```sql
CREATE TABLE signups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES events(id),
    signer_uid VARCHAR(50) NOT NULL,
    signer_name VARCHAR(255) NOT NULL,
    signer_ssn_hash BYTEA NOT NULL, -- SHA256(ssn), not reversible
    signer_cert_thumbprint VARCHAR(64) NOT NULL, -- SHA256 of DER cert
    signup_path VARCHAR(20) NOT NULL, -- "mtls" or "pades"
    signature_status VARCHAR(50) NOT NULL, -- "valid", "pending", "failed"

    -- For PAdES only
    pdf_document_id UUID,
    signature_cms_base64 TEXT,
    signature_algorithm VARCHAR(50),

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP WITH TIME ZONE,

    -- Immutable hash for tamper detection
    content_hash BYTEA NOT NULL,

    CONSTRAINT valid_path CHECK (signup_path IN ('mtls', 'pades')),
    UNIQUE(event_id, signer_cert_thumbprint, created_at) -- Prevent duplicates
);

CREATE INDEX idx_signups_event_id ON signups(event_id);
CREATE INDEX idx_signups_signer_uid ON signups(signer_uid);
CREATE INDEX idx_signups_created_at ON signups(created_at DESC);
```

**Table: `audit_log`**
```sql
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id UUID,
    actor_uid VARCHAR(50), -- System user or signer UID
    actor_ip_address INET,
    actor_cert_thumbprint VARCHAR(64),

    -- Immutable record
    event_data JSONB NOT NULL,
    result_status VARCHAR(20) NOT NULL, -- "success", "failure"
    error_message TEXT,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Content-addressable storage: hash of this record
    content_hash BYTEA NOT NULL,
    previous_hash BYTEA, -- Points to previous log entry (blockchain-like)

    CONSTRAINT valid_action CHECK (action IN (
        'signup_created', 'signature_verified', 'certificate_validated',
        'document_generated', 'audit_export', 'policy_change'
    ))
);

CREATE INDEX idx_audit_log_created_at ON audit_log(created_at DESC);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_entity ON audit_log(entity_type, entity_id);
```

**Table: `documents`** (for PAdES)
```sql
CREATE TABLE documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES events(id),
    document_type VARCHAR(50) NOT NULL, -- "sign_in_sheet", "attestation", "approval"

    -- Original unsigned PDF
    pdf_content BYTEA NOT NULL,
    pdf_hash BYTEA NOT NULL, -- SHA256 of content

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE, -- Optional: doc expires after X days

    CONSTRAINT valid_type CHECK (document_type IN ('sign_in_sheet', 'attestation', 'approval'))
);

CREATE INDEX idx_documents_event_id ON documents(event_id);
```

**Table: `dot_root_certificates`** (PKI Trust Store)
```sql
CREATE TABLE dot_root_certificates (
    id SERIAL PRIMARY KEY,
    certificate_name VARCHAR(255) NOT NULL UNIQUE,
    certificate_der BYTEA NOT NULL,
    thumbprint VARCHAR(64) NOT NULL UNIQUE,
    issuer_cn VARCHAR(255) NOT NULL,
    valid_from TIMESTAMP WITH TIME ZONE,
    valid_to TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT valid_dates CHECK (valid_from < valid_to)
);

-- Pre-populate with DOD Root CA 3, DOD Root CA 4, etc.
```

---

## Cryptographic Operations

### Algorithms (FIPS 140-3 Approved)

| Operation | Algorithm | Key Size | Library |
|-----------|-----------|----------|---------|
| Hash | SHA-256 | 256-bit | crypto/sha256 |
| Hash | SHA-512 | 512-bit | crypto/sha512 |
| Digital Signature | RSA-PSS | 2048+ bits | crypto/rsa |
| Digital Signature | ECDSA | P-256, P-384 | crypto/ecdsa |
| Symmetric Encryption | AES-GCM | 256-bit | crypto/aes |
| TLS | TLS 1.3 | - | crypto/tls |
| MAC | HMAC-SHA256 | 256-bit | crypto/hmac |

**NO DEPRECATED ALGORITHMS:**
- ❌ RSA-PKCS#1 v1.5 (use PSS only)
- ❌ MD5, SHA-1 (legacy only for cert validation, not new)
- ❌ TLS 1.0, 1.1, 1.2 for new connections (1.3 minimum)
- ❌ Weak symmetric ciphers

### Audit Log Integrity

Create tamper-evident audit log using content-addressable hashing:

```go
type AuditLogEntry struct {
    ID              uint64
    Action          string
    EntityType      string
    EntityID        string
    ActorUID        string
    EventData       json.RawMessage
    ResultStatus    string
    CreatedAt       time.Time

    // Integrity chain
    ContentHash     []byte // SHA256 of this record
    PreviousHash    []byte // SHA256 of previous record
}

func (entry *AuditLogEntry) ComputeHash() []byte {
    h := sha256.New()
    // Write all fields to hash
    fmt.Fprintf(h, "%d:%s:%s:%s:%s:%s:%d:%s",
        entry.ID,
        entry.Action,
        entry.EntityType,
        entry.ActorUID,
        string(entry.EventData),
        entry.CreatedAt.Unix(),
        entry.PreviousHash, // Include previous hash in chain
    )
    return h.Sum(nil)
}
```

If any audit log entry is modified, the hash chain breaks, exposing tampering.

---

## API Endpoints

### Path 1: mTLS Sign-Up

**`POST /api/v1/signups/mtls`**
- **Auth:** mTLS (CAC certificate required)
- **Body:** MTLSSignUpRequest
- **Response:** SignUpResponse
- **Side Effects:** Creates signup record, audit log entry, certificate validation record

```bash
# Client command (assumes CAC cert in client-cert.pem, key in client-key.pem)
curl --cert client-cert.pem --key client-key.pem \
     --cacert dod-root.pem \
     https://api.signonduty.mil/api/v1/signups/mtls \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"event_name":"Safety Training","event_date":"2025-10-28"}'
```

### Path 2: PAdES Sign-Up

**`POST /api/v1/signups/documents`** (Generate unsigned PDF)
- **Auth:** API Key or JWT (not CAC, yet)
- **Body:** DocumentRequest
- **Response:** DocumentResponse (includes PDF)

**`POST /api/v1/signups/verify-pdf`** (Verify signed PDF)
- **Auth:** None (PDF contains signature)
- **Body:** PDFVerificationRequest (multipart/form-data with PDF)
- **Response:** SignatureValidation + SignUpResponse
- **Side Effects:** Verifies signature, extracts signer, creates signup record, audit log

### Shared Endpoints

**`GET /api/v1/events/{eventID}/signups`**
- **Auth:** Bearer token (admin)
- **Response:** List of signups for event
- **Filters:** date range, signer name, signature status

**`GET /api/v1/signups/{signupID}/audit`**
- **Auth:** Bearer token (admin or self)
- **Response:** Complete audit trail for signup
- **Content:** All actions related to signup, certificate validations, verifications

**`POST /api/v1/admin/verify-certificate`** (Manual verification)
- **Auth:** Bearer token (admin)
- **Body:** Certificate in DER or PEM format
- **Response:** CertificateValidation result

---

## Security Considerations

### 1. Certificate Revocation (CRL/OCSP)

Implement real-time certificate revocation checking:

```go
// For each CAC certificate presented:
// 1. Check embedded CRL Distribution Point
// 2. Attempt OCSP request to OCSP responder
// 3. Cache result with TTL (4 hours recommended)
// 4. Reject if revocation check fails (fail-closed)
```

**Implementation:**
- Use `crypto/x509` package for CRL parsing
- Implement OCSP stapling for mTLS
- Background job to pre-fetch CRLs from DOD PKI

### 2. PIN Entry Security

For PAdES signing:
- ❌ Never capture or transmit CAC PIN over network
- ✅ CAC PIN entry happens entirely on client system (Acrobat/Outlook)
- ✅ Server never sees PIN, only signed result

### 3. Audit Log Protection

- **Immutable:** No DELETE or UPDATE statements (INSERT-only)
- **Tamper-evident:** Content hash chain
- **Encrypted at rest:** AES-256-GCM
- **Separated storage:** Move audit logs to read-only replica after N hours
- **Secure export:** Signed/timestamped backup exports

### 4. Database Security

```sql
-- Enable at-rest encryption
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = '/etc/postgresql/server.crt';
ALTER SYSTEM SET ssl_key_file = '/etc/postgresql/server.key';

-- Enable connection encryption
CREATE USER webapp WITH ENCRYPTED PASSWORD 'strong_random_password';
GRANT CONNECT ON DATABASE signonduty TO webapp;

-- Row-level security
ALTER TABLE signups ENABLE ROW LEVEL SECURITY;
CREATE POLICY rls_admin ON signups TO admin USING (true);
CREATE POLICY rls_user ON signups TO webapp
    USING (signer_uid = current_user_id);
```

### 5. TLS Configuration

```go
// Server configuration
tlsConfig := &tls.Config{
    MinVersion:               tls.VersionTLS13,
    PreferServerCipherSuites: true,
    CipherSuites: []uint16{
        tls.TLS_AES_256_GCM_SHA384,
        tls.TLS_CHACHA20_POLY1305_SHA256,
        tls.TLS_AES_128_GCM_SHA256,
    },
    Certificates: []tls.Certificate{...},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    dotRootCertPool,
}
```

---

## Deployment on AWS

### Architecture Diagram

```
Internet
   ↓
[AWS API Gateway - mTLS]
   ↓
[Network Load Balancer]
   ↓
[ECS/EC2 - SignOnDuty Backend]
   ↓
[RDS PostgreSQL - Encrypted]
   ↓
[S3 - Signed PDFs, Encrypted]
```

### FIPS-Compliant AWS Services

- **EC2 with Nitro Security Module:** Hardware-backed encryption
- **RDS PostgreSQL:** FIPS mode, encrypted at rest (AWS KMS), encrypted in transit (SSL)
- **AWS Secrets Manager:** FIPS-compliant secret storage
- **API Gateway with mTLS:** Mutual TLS termination
- **KMS:** FIPS 140-2 Level 2 hardware security module (HSM)
- **CloudTrail:** Immutable audit logging

### Infrastructure-as-Code (Terraform)

```hcl
# AWS KMS key for encryption
resource "aws_kms_key" "signonduty" {
  description             = "SignOnDuty encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_policy.json
}

# RDS PostgreSQL with encryption
resource "aws_rds_cluster" "signonduty" {
  cluster_identifier              = "signonduty-db"
  engine                          = "aurora-postgresql"
  engine_version                  = "15.3" # Latest with FIPS
  database_name                   = "signonduty"
  master_username                 = var.db_master_user
  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.signonduty.arn
  enable_cloudwatch_logs_exports  = ["postgresql"]
  backup_retention_period         = 30
  deletion_protection             = true
}

# API Gateway with Client Certificate
resource "aws_api_gateway_domain_name" "signonduty" {
  domain_name            = "api.signonduty.mil"
  certificate_arn        = aws_acm_certificate.signonduty.arn
  mutual_tls_auth_enabled = true
  # Client certificate trust store configured via AWS Certificate Manager
}
```

---

## Compliance & Audit

### Regular Audits Required

1. **Annual Security Assessment:** NIST SP 800-53 controls
2. **Quarterly Certificate Audits:** Verify all certificates still valid/trusted
3. **Monthly Audit Log Review:** Sample audit logs for tampering
4. **Continuous Monitoring:** CloudWatch alarms for suspicious activities

### Compliance Artifacts to Generate

1. **System Security Plan (SSP):** Document all controls and their implementation
2. **Risk Assessment:** Identify potential threats and mitigations
3. **Incident Response Plan:** Procedures if certificate revoked or breach detected
4. **Configuration Management Plan:** Track all infrastructure changes
5. **Security Test Report:** Annual penetration testing results

---

## Development Timeline

| Phase | Duration | Deliverables |
|-------|----------|--------------|
| Phase 1 | 2 weeks | Project structure, PKI integration, database |
| Phase 2 | 3 weeks | mTLS authentication, sign-up flow |
| Phase 3 | 3 weeks | PAdES/CMS implementation, PDF signing |
| Phase 4 | 2 weeks | Audit logging, tamper detection |
| Phase 5 | 2 weeks | AWS deployment, FIPS configuration |
| Phase 6 | 2 weeks | Security testing, compliance review |

---

## Next Steps

1. ✅ Create project structure
2. ⏳ Initialize Go backend with Echo framework
3. ⏳ Set up PostgreSQL schema
4. ⏳ Implement CAC certificate validation
5. ⏳ Build mTLS sign-up endpoint
6. ⏳ Implement PAdES signing workflow
7. ⏳ Deploy to AWS with FIPS configuration
