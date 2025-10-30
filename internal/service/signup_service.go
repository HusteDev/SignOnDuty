package service

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/thana/signonduty/internal/model"
	"github.com/thana/signonduty/internal/repository"
)

// SignupService handles signup business logic
type SignupService struct {
	signupRepo  *repository.SignupRepository
	auditRepo   *repository.AuditLogRepository
	pkiService  *PKIService
}

func NewSignupService(
	signupRepo *repository.SignupRepository,
	auditRepo *repository.AuditLogRepository,
	pkiService *PKIService,
) *SignupService {
	return &SignupService{
		signupRepo: signupRepo,
		auditRepo:  auditRepo,
		pkiService: pkiService,
	}
}

// CreateMTLSSignup creates a signup from an mTLS authenticated request
func (s *SignupService) CreateMTLSSignup(
	eventID uuid.UUID,
	clientCert *x509.Certificate,
	clientIP string,
) (*model.Signup, error) {
	// 1. Validate CAC certificate
	validation, err := s.pkiService.ValidateCAC(clientCert)
	if err != nil {
		// Log failed validation
		s.logAuditEvent(model.AuditLogEntry{
			Action:      "certificate_validated",
			EntityType:  "certificate",
			ActorType:   "system",
			ActorIPAddress: clientIP,
			ResultStatus: "failure",
			EventData: map[string]interface{}{
				"reason": err.Error(),
			},
		})
		return nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	if !validation.Valid {
		// Log failed validation
		s.logAuditEvent(model.AuditLogEntry{
			Action:      "certificate_validated",
			EntityType:  "certificate",
			ActorType:   "system",
			ActorIPAddress: clientIP,
			ResultStatus: "failure",
			EventData: map[string]interface{}{
				"reason": validation.ErrorMessage,
				"status": validation.ValidationStatus,
			},
		})
		return nil, fmt.Errorf("certificate validation failed: %s", validation.ErrorMessage)
	}

	identity := validation.Identity

	// 2. Check for duplicate signup (same cert, same event)
	thumbprint := s.pkiService.GetCertificateThumbprint(clientCert)
	existing, err := s.signupRepo.GetSignupByCertThumbprint(eventID, thumbprint)
	if err != nil {
		return nil, fmt.Errorf("failed to check for existing signup: %w", err)
	}

	if existing != nil {
		return nil, fmt.Errorf("certificate already signed for this event")
	}

	// 3. Create signup record
	signup := &model.Signup{
		EventID:               eventID,
		SignerUID:             identity.FirstName + "." + identity.LastName,
		SignerName:            identity.FirstName + " " + identity.LastName,
		SignerOrganization:    identity.Organization,
		SignerCertThumbprint:  thumbprint,
		SignerCertSubjectDN:   identity.DistinguishedName,
		SignupPath:            "mtls",
		SignatureStatus:       "valid",
		TLSConnectionInfo: map[string]string{
			"client_ip":      clientIP,
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
			"cert_thumbprint": thumbprint,
		},
		ApprovalStatus: "none",
	}

	// Hash SSN for storage
	ssn := identity.SSN
	if len(ssn) >= 4 {
		signup.SignerSSNLast4 = ssn[len(ssn)-4:]
		// In real scenario, hash full SSN
		ssnHash := sha256.Sum256([]byte(ssn))
		signup.SignerSSNHash = ssnHash[:]
	}

	// Compute content hash for tamper detection
	signup.ContentHash = s.computeSignupHash(signup)

	// 4. Store signup in database
	err = s.signupRepo.CreateSignup(signup)
	if err != nil {
		errMsg := err.Error()
		s.logAuditEvent(model.AuditLogEntry{
			Action:         "signup_created",
			EntityType:     "signup",
			EntityID:       &signup.ID,
			ActorType:      "system",
			ActorUID:       &signup.SignerUID,
			ActorIPAddress: clientIP,
			ResultStatus:   "failure",
			ErrorMessage:   &errMsg,
		})
		return nil, fmt.Errorf("failed to create signup: %w", err)
	}

	// 5. Log successful signup
	s.logAuditEvent(model.AuditLogEntry{
		Action:          "signup_created",
		EntityType:      "signup",
		EntityID:        &signup.ID,
		ActorType:       "user",
		ActorUID:        &signup.SignerUID,
		ActorIPAddress:  clientIP,
		ActorCertThumbprint: &thumbprint,
		ResultStatus:    "success",
		EventData: map[string]interface{}{
			"event_id":  eventID,
			"signer":    signup.SignerName,
			"path":      "mtls",
		},
	})

	return signup, nil
}

// VerifySignedPDF verifies a PAdES signature and creates signup record
func (s *SignupService) VerifySignedPDF(
	documentID uuid.UUID,
	signedPDFData []byte,
	clientIP string,
) (*model.Signup, error) {
	// 1. Extract certificate and signature from signed PDF
	// This would use a PDF library like pdfcpu
	// For now, this is a stub implementation

	return nil, fmt.Errorf("PAdES verification not yet implemented")
}

// GetSignupByID retrieves a signup
func (s *SignupService) GetSignupByID(signupID uuid.UUID) (*model.Signup, error) {
	return s.signupRepo.GetSignupByID(signupID)
}

// ListSignupsByEventID lists all signups for an event
func (s *SignupService) ListSignupsByEventID(eventID uuid.UUID) ([]*model.Signup, error) {
	return s.signupRepo.ListSignupsByEventID(eventID)
}

// GetSignupAuditTrail retrieves audit logs for a signup
func (s *SignupService) GetSignupAuditTrail(signupID uuid.UUID) ([]*model.AuditLogEntry, error) {
	return s.auditRepo.GetAuditLogByEntity("signup", signupID)
}

// ApproveSignup marks a signup as approved
func (s *SignupService) ApproveSignup(signupID uuid.UUID, approverUID, notes string) error {
	err := s.signupRepo.UpdateApprovalStatus(signupID, "approved", approverUID, notes)
	if err != nil {
		return fmt.Errorf("failed to approve signup: %w", err)
	}

	// Log approval
	s.logAuditEvent(model.AuditLogEntry{
		Action:     "approval_granted",
		EntityType: "signup",
		EntityID:   &signupID,
		ActorType:  "user",
		ActorUID:   &approverUID,
		ResultStatus: "success",
		EventData: map[string]interface{}{
			"approval_notes": notes,
		},
	})

	return nil
}

// RejectSignup marks a signup as rejected
func (s *SignupService) RejectSignup(signupID uuid.UUID, approverUID, notes string) error {
	err := s.signupRepo.UpdateApprovalStatus(signupID, "rejected", approverUID, notes)
	if err != nil {
		return fmt.Errorf("failed to reject signup: %w", err)
	}

	// Log rejection
	s.logAuditEvent(model.AuditLogEntry{
		Action:     "approval_rejected",
		EntityType: "signup",
		EntityID:   &signupID,
		ActorType:  "user",
		ActorUID:   &approverUID,
		ResultStatus: "success",
		EventData: map[string]interface{}{
			"rejection_reason": notes,
		},
	})

	return nil
}

// VerifySignupIntegrity checks if a signup has been tampered with
func (s *SignupService) VerifySignupIntegrity(signup *model.Signup) (bool, error) {
	currentHash := s.computeSignupHash(signup)

	return sha256.Sum256(currentHash) == sha256.Sum256(signup.ContentHash), nil
}

// computeSignupHash computes a hash of critical signup fields for tamper detection
func (s *SignupService) computeSignupHash(signup *model.Signup) []byte {
	h := sha256.New()

	// Write critical fields to hash
	fmt.Fprintf(h, "%s:%s:%s:%s:%s:%s",
		signup.EventID.String(),
		signup.SignerUID,
		signup.SignerCertThumbprint,
		signup.SignupPath,
		signup.SignatureStatus,
		signup.CreatedAt.Format(time.RFC3339),
	)

	return h.Sum(nil)
}

// logAuditEvent creates an audit log entry
func (s *SignupService) logAuditEvent(entry model.AuditLogEntry) error {
	// Compute content hash for this audit entry
	entry.ContentHash = s.computeAuditLogHash(entry)

	return s.auditRepo.CreateAuditLog(&entry)
}

// computeAuditLogHash computes hash for audit log entry
func (s *SignupService) computeAuditLogHash(entry model.AuditLogEntry) []byte {
	h := sha256.New()

	eventDataJSON, _ := json.Marshal(entry.EventData)

	fmt.Fprintf(h, "%s:%s:%s:%s:%s",
		entry.Action,
		entry.EntityType,
		entry.ResultStatus,
		string(eventDataJSON),
		entry.CreatedAt.Format(time.RFC3339),
	)

	return h.Sum(nil)
}
