package model

import (
	"crypto/x509"
	"time"

	"github.com/google/uuid"
)

// CACIdentity represents extracted CAC certificate subject information
type CACIdentity struct {
	FirstName         string
	LastName          string
	SSN               string // Last 4 only for display, full only in audit
	Organization      string
	DistinguishedName string
	Thumbprint        string // SHA256 cert hash
}

// Event represents a sign-up event (e.g., training, meeting, inspection)
type Event struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	Name            string     `json:"name" db:"name"`
	Description     string     `json:"description" db:"description"`
	EventType       string     `json:"event_type" db:"event_type"` // "attendance", "approval", "attestation"
	StartDate       time.Time  `json:"start_date" db:"start_date"`
	EndDate         *time.Time `json:"end_date" db:"end_date"`
	Location        string     `json:"location" db:"location"`
	OrganizerUID    string     `json:"organizer_uid" db:"organizer_uid"`
	SigningMethod   string     `json:"signing_method" db:"signing_method"` // "mtls", "pades", "both"
	RequireApproval bool       `json:"require_approval" db:"require_approval"`
	IsActive        bool       `json:"is_active" db:"is_active"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

// Signup represents a sign-up submission
type Signup struct {
	ID                   uuid.UUID          `json:"id" db:"id"`
	EventID              uuid.UUID          `json:"event_id" db:"event_id"`
	SignerUID            string             `json:"signer_uid" db:"signer_uid"`
	SignerName           string             `json:"signer_name" db:"signer_name"`
	SignerOrganization   string             `json:"signer_organization" db:"signer_organization"`
	SignerSSNHash        []byte             `json:"-" db:"signer_ssn_hash"` // Never expose hash
	SignerSSNLast4       string             `json:"signer_ssn_last4" db:"signer_ssn_last4"`
	SignerCertThumbprint string             `json:"signer_cert_thumbprint" db:"signer_cert_thumbprint"`
	SignerCertSubjectDN  string             `json:"signer_cert_subject_dn" db:"signer_cert_subject_dn"`
	SignupPath           string             `json:"signup_path" db:"signup_path"` // "mtls", "pades"
	SignatureStatus      string             `json:"signature_status" db:"signature_status"`
	PDFDocumentID        *uuid.UUID         `json:"pdf_document_id" db:"pdf_document_id"`
	SignatureCMSBase64   string             `json:"-" db:"signature_cms_base64"` // Only for verified signatures
	SignatureAlgorithm   string             `json:"signature_algorithm" db:"signature_algorithm"`
	SignatureTimestamp   *time.Time         `json:"signature_timestamp" db:"signature_timestamp"`
	TLSConnectionInfo    map[string]string  `json:"tls_connection_info" db:"tls_connection_info"` // JSONB
	ApprovalStatus       string             `json:"approval_status" db:"approval_status"`
	ApprovedByUID        *string            `json:"approved_by_uid" db:"approved_by_uid"`
	ApprovedAt           *time.Time         `json:"approved_at" db:"approved_at"`
	ApprovalNotes        string             `json:"approval_notes" db:"approval_notes"`
	CreatedAt            time.Time          `json:"created_at" db:"created_at"`
	VerifiedAt           *time.Time         `json:"verified_at" db:"verified_at"`
	ContentHash          []byte             `json:"-" db:"content_hash"` // Tamper detection
	ClientCertificate    *x509.Certificate `json:"-" db:"-"`             // Populated from request
}

// Document represents a PDF for signing
type Document struct {
	ID              uuid.UUID `json:"id" db:"id"`
	EventID         uuid.UUID `json:"event_id" db:"event_id"`
	DocumentType    string    `json:"document_type" db:"document_type"` // "sign_in_sheet", "attestation", "approval"
	PDFContent      []byte    `json:"-" db:"pdf_content"`
	PDFHash         []byte    `json:"-" db:"pdf_hash"`
	PDFSize         int64     `json:"pdf_size" db:"pdf_size"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	ExpiresAt       *time.Time `json:"expires_at" db:"expires_at"`
	IsTemplate      bool      `json:"is_template" db:"is_template"`
	CreatedByUID    string    `json:"created_by_uid" db:"created_by_uid"`
}

// AuditLogEntry represents an immutable audit log entry
type AuditLogEntry struct {
	ID                   int64           `json:"id" db:"id"`
	Action               string          `json:"action" db:"action"`
	EntityType           string          `json:"entity_type" db:"entity_type"`
	EntityID             *uuid.UUID      `json:"entity_id" db:"entity_id"`
	ActorType            string          `json:"actor_type" db:"actor_type"`
	ActorUID             *string         `json:"actor_uid" db:"actor_uid"`
	ActorIPAddress       string          `json:"actor_ip_address" db:"actor_ip_address"`
	ActorCertThumbprint  *string         `json:"actor_cert_thumbprint" db:"actor_cert_thumbprint"`
	ResultStatus         string          `json:"result_status" db:"result_status"`
	ErrorMessage         *string         `json:"error_message" db:"error_message"`
	EventData            map[string]interface{} `json:"event_data" db:"event_data"`
	CreatedAt            time.Time       `json:"created_at" db:"created_at"`
	ContentHash          []byte          `json:"-" db:"content_hash"`
	PreviousEntryHash    *[]byte         `json:"-" db:"previous_entry_hash"`
}

// CertificateValidation represents the result of certificate validation
type CertificateValidation struct {
	Valid              bool
	Identity           *CACIdentity
	CertificateChain   []*x509.Certificate
	ValidationStatus   string // "valid", "expired", "untrusted_root", "revoked"
	ValidationTime     time.Time
	ErrorMessage       string
}

// MTLSSignUpRequest represents the request body for mTLS sign-up
type MTLSSignUpRequest struct {
	EventName    string                 `json:"event_name" validate:"required"`
	EventDate    time.Time              `json:"event_date" validate:"required"`
	EventType    string                 `json:"event_type"`
	CustomFields map[string]interface{} `json:"custom_fields"`
}

// SignUpResponse represents the response after successful sign-up
type SignUpResponse struct {
	SignUpID      string    `json:"signup_id"`
	Timestamp     time.Time `json:"timestamp"`
	SignerName    string    `json:"signer_name"`
	VerifyToken   string    `json:"verify_token"` // For client verification
}

// DocumentRequest represents a request to generate a signing document
type DocumentRequest struct {
	EventID    string `json:"event_id" validate:"required"`
	EventName  string `json:"event_name"`
	EventDate  time.Time `json:"event_date"`
	Language   string `json:"language"` // "en", "es"
	ReturnURL  string `json:"return_url"`
}

// DocumentResponse represents the response with a PDF document
type DocumentResponse struct {
	DocumentID  string `json:"document_id"`
	PDFBase64   string `json:"pdf_base64"`
	DocumentURL string `json:"document_url"` // S3 pre-signed URL
}

// PDFVerificationRequest represents a request to verify a signed PDF
type PDFVerificationRequest struct {
	DocumentID string `json:"document_id" form:"document_id"`
	PDFBase64  string `json:"pdf_base64" form:"pdf_base64"`
}

// SignatureValidation represents verified signature details
type SignatureValidation struct {
	Valid              bool
	SignedBy           *CACIdentity
	SignatureTime      time.Time
	CertificateChain   []*x509.Certificate
	SignatureAlgorithm string
	Timestamp          time.Time
	SignUpID           string
}

// User represents a system user
type User struct {
	UID             string    `json:"uid" db:"uid"`
	Name            string    `json:"name" db:"name"`
	Email           string    `json:"email" db:"email"`
	Role            string    `json:"role" db:"role"` // "user", "event_organizer", "approver", "auditor", "admin"
	CertThumbprint  string    `json:"cert_thumbprint" db:"cert_thumbprint"`
	IsActive        bool      `json:"is_active" db:"is_active"`
	LastLogin       *time.Time `json:"last_login" db:"last_login"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

// ApprovalRequest represents an approval workflow request
type ApprovalRequest struct {
	ID               uuid.UUID  `json:"id" db:"id"`
	SignupID         uuid.UUID  `json:"signup_id" db:"signup_id"`
	ApproverUID      string     `json:"approver_uid" db:"approver_uid"`
	Status           string     `json:"status" db:"status"` // "pending", "approved", "rejected"
	RequesterNotes   string     `json:"requester_notes" db:"requester_notes"`
	ApproverNotes    string     `json:"approver_notes" db:"approver_notes"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
	RespondedAt      *time.Time `json:"responded_at" db:"responded_at"`
	ResponseDeadline *time.Time `json:"response_deadline" db:"response_deadline"`
}

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// DODRootCert represents a DOD root certificate
type DODRootCert struct {
	CertificateName string
	CertificateDER  []byte
	Thumbprint      string
	IssuerCN        string
	ValidFrom       time.Time
	ValidTo         time.Time
	IsActive        bool
}
