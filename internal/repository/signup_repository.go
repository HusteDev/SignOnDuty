package repository

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/thana/signonduty/internal/model"
)

type SignupRepository struct {
	db *sql.DB
}

func NewSignupRepository(db *sql.DB) *SignupRepository {
	return &SignupRepository{db: db}
}

// CreateSignup creates a new signup record
func (r *SignupRepository) CreateSignup(signup *model.Signup) error {
	tlsInfoJSON, err := json.Marshal(signup.TLSConnectionInfo)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO signups (
			event_id, signer_uid, signer_name, signer_organization,
			signer_ssn_hash, signer_ssn_last4, signer_cert_thumbprint,
			signer_cert_subject_dn, signup_path, signature_status,
			tls_connection_info, approval_status, created_at, content_hash
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		) RETURNING id, created_at
	`

	err = r.db.QueryRow(
		query,
		signup.EventID,
		signup.SignerUID,
		signup.SignerName,
		signup.SignerOrganization,
		signup.SignerSSNHash,
		signup.SignerSSNLast4,
		signup.SignerCertThumbprint,
		signup.SignerCertSubjectDN,
		signup.SignupPath,
		signup.SignatureStatus,
		tlsInfoJSON,
		"none", // approval_status
		time.Now().UTC(),
		signup.ContentHash,
	).Scan(&signup.ID, &signup.CreatedAt)

	return err
}

// GetSignupByID retrieves a signup by ID
func (r *SignupRepository) GetSignupByID(signupID uuid.UUID) (*model.Signup, error) {
	query := `
		SELECT
			id, event_id, signer_uid, signer_name, signer_organization,
			signer_cert_thumbprint, signer_cert_subject_dn, signup_path,
			signature_status, pdf_document_id, signature_algorithm,
			signature_timestamp, approval_status, approved_by_uid,
			approved_at, created_at, verified_at, signer_ssn_last4,
			tls_connection_info, content_hash
		FROM signups
		WHERE id = $1
	`

	var signup model.Signup
	var tlsInfoJSON []byte
	var approvedByUID sql.NullString
	var approvedAt sql.NullTime
	var verifiedAt sql.NullTime
	var signatureTimestamp sql.NullTime

	err := r.db.QueryRow(query, signupID).Scan(
		&signup.ID,
		&signup.EventID,
		&signup.SignerUID,
		&signup.SignerName,
		&signup.SignerOrganization,
		&signup.SignerCertThumbprint,
		&signup.SignerCertSubjectDN,
		&signup.SignupPath,
		&signup.SignatureStatus,
		&signup.PDFDocumentID,
		&signup.SignatureAlgorithm,
		&signatureTimestamp,
		&signup.ApprovalStatus,
		&approvedByUID,
		&approvedAt,
		&signup.CreatedAt,
		&verifiedAt,
		&signup.SignerSSNLast4,
		&tlsInfoJSON,
		&signup.ContentHash,
	)

	if err != nil {
		return nil, err
	}

	// Parse TLS info JSON
	if len(tlsInfoJSON) > 0 {
		err = json.Unmarshal(tlsInfoJSON, &signup.TLSConnectionInfo)
		if err != nil {
			return nil, err
		}
	}

	if approvedByUID.Valid {
		signup.ApprovedByUID = &approvedByUID.String
	}
	if approvedAt.Valid {
		signup.ApprovedAt = &approvedAt.Time
	}
	if verifiedAt.Valid {
		signup.VerifiedAt = &verifiedAt.Time
	}
	if signatureTimestamp.Valid {
		signup.SignatureTimestamp = &signatureTimestamp.Time
	}

	return &signup, nil
}

// ListSignupsByEventID retrieves all signups for an event
func (r *SignupRepository) ListSignupsByEventID(eventID uuid.UUID) ([]*model.Signup, error) {
	query := `
		SELECT
			id, event_id, signer_uid, signer_name, signer_organization,
			signer_cert_thumbprint, signer_cert_subject_dn, signup_path,
			signature_status, pdf_document_id, signature_algorithm,
			signature_timestamp, approval_status, approved_by_uid,
			approved_at, created_at, verified_at, signer_ssn_last4,
			tls_connection_info, content_hash
		FROM signups
		WHERE event_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(query, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var signups []*model.Signup

	for rows.Next() {
		var signup model.Signup
		var tlsInfoJSON []byte
		var approvedByUID sql.NullString
		var approvedAt sql.NullTime
		var verifiedAt sql.NullTime
		var signatureTimestamp sql.NullTime

		err := rows.Scan(
			&signup.ID,
			&signup.EventID,
			&signup.SignerUID,
			&signup.SignerName,
			&signup.SignerOrganization,
			&signup.SignerCertThumbprint,
			&signup.SignerCertSubjectDN,
			&signup.SignupPath,
			&signup.SignatureStatus,
			&signup.PDFDocumentID,
			&signup.SignatureAlgorithm,
			&signatureTimestamp,
			&signup.ApprovalStatus,
			&approvedByUID,
			&approvedAt,
			&signup.CreatedAt,
			&verifiedAt,
			&signup.SignerSSNLast4,
			&tlsInfoJSON,
			&signup.ContentHash,
		)

		if err != nil {
			return nil, err
		}

		if len(tlsInfoJSON) > 0 {
			err = json.Unmarshal(tlsInfoJSON, &signup.TLSConnectionInfo)
			if err != nil {
				return nil, err
			}
		}

		if approvedByUID.Valid {
			signup.ApprovedByUID = &approvedByUID.String
		}
		if approvedAt.Valid {
			signup.ApprovedAt = &approvedAt.Time
		}
		if verifiedAt.Valid {
			signup.VerifiedAt = &verifiedAt.Time
		}
		if signatureTimestamp.Valid {
			signup.SignatureTimestamp = &signatureTimestamp.Time
		}

		signups = append(signups, &signup)
	}

	return signups, rows.Err()
}

// UpdateSignupStatus updates the signature status of a signup
func (r *SignupRepository) UpdateSignupStatus(signupID uuid.UUID, status string, verifiedAt time.Time) error {
	query := `
		UPDATE signups
		SET signature_status = $1, verified_at = $2, updated_at = CURRENT_TIMESTAMP
		WHERE id = $3
	`

	_, err := r.db.Exec(query, status, verifiedAt, signupID)
	return err
}

// GetSignupByCertThumbprint checks if a certificate has already signed
func (r *SignupRepository) GetSignupByCertThumbprint(eventID uuid.UUID, thumbprint string) (*model.Signup, error) {
	query := `
		SELECT
			id, event_id, signer_uid, signer_name, signer_organization,
			signer_cert_thumbprint, signer_cert_subject_dn, signup_path,
			signature_status, pdf_document_id, signature_algorithm,
			signature_timestamp, approval_status, created_at, verified_at,
			signer_ssn_last4, content_hash
		FROM signups
		WHERE event_id = $1 AND signer_cert_thumbprint = $2
		LIMIT 1
	`

	var signup model.Signup
	var verifiedAt sql.NullTime
	var signatureTimestamp sql.NullTime

	err := r.db.QueryRow(query, eventID, thumbprint).Scan(
		&signup.ID,
		&signup.EventID,
		&signup.SignerUID,
		&signup.SignerName,
		&signup.SignerOrganization,
		&signup.SignerCertThumbprint,
		&signup.SignerCertSubjectDN,
		&signup.SignupPath,
		&signup.SignatureStatus,
		&signup.PDFDocumentID,
		&signup.SignatureAlgorithm,
		&signatureTimestamp,
		&signup.ApprovalStatus,
		&signup.CreatedAt,
		&verifiedAt,
		&signup.SignerSSNLast4,
		&signup.ContentHash,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if verifiedAt.Valid {
		signup.VerifiedAt = &verifiedAt.Time
	}
	if signatureTimestamp.Valid {
		signup.SignatureTimestamp = &signatureTimestamp.Time
	}

	return &signup, nil
}

// ApprovalsRequired checks if approvals are required
func (r *SignupRepository) UpdateApprovalStatus(signupID uuid.UUID, status, approverUID, notes string) error {
	query := `
		UPDATE signups
		SET approval_status = $1, approved_by_uid = $2, approved_at = CURRENT_TIMESTAMP, approval_notes = $3
		WHERE id = $4
	`

	_, err := r.db.Exec(query, status, approverUID, notes, signupID)
	return err
}
