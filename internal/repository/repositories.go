package repository

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/thana/signonduty/internal/model"
)

// EventRepository handles event data operations
type EventRepository struct {
	db *sql.DB
}

func NewEventRepository(db *sql.DB) *EventRepository {
	return &EventRepository{db: db}
}

func (r *EventRepository) CreateEvent(event *model.Event) error {
	query := `
		INSERT INTO events (name, description, event_type, start_date, end_date, location, organizer_uid, signing_method, require_approval, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, created_at, updated_at
	`

	return r.db.QueryRow(
		query,
		event.Name,
		event.Description,
		event.EventType,
		event.StartDate,
		event.EndDate,
		event.Location,
		event.OrganizerUID,
		event.SigningMethod,
		event.RequireApproval,
		event.IsActive,
		time.Now().UTC(),
		time.Now().UTC(),
	).Scan(&event.ID, &event.CreatedAt, &event.UpdatedAt)
}

func (r *EventRepository) GetEventByID(eventID uuid.UUID) (*model.Event, error) {
	query := `
		SELECT id, name, description, event_type, start_date, end_date, location, organizer_uid, signing_method, require_approval, is_active, created_at, updated_at
		FROM events
		WHERE id = $1 AND is_active = true
	`

	var event model.Event
	var endDate sql.NullTime

	err := r.db.QueryRow(query, eventID).Scan(
		&event.ID, &event.Name, &event.Description, &event.EventType,
		&event.StartDate, &endDate, &event.Location, &event.OrganizerUID,
		&event.SigningMethod, &event.RequireApproval, &event.IsActive,
		&event.CreatedAt, &event.UpdatedAt,
	)

	if endDate.Valid {
		event.EndDate = &endDate.Time
	}

	return &event, err
}

func (r *EventRepository) ListEvents() ([]*model.Event, error) {
	query := `
		SELECT id, name, description, event_type, start_date, end_date, location, organizer_uid, signing_method, require_approval, is_active, created_at, updated_at
		FROM events
		WHERE is_active = true
		ORDER BY start_date DESC
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*model.Event

	for rows.Next() {
		var event model.Event
		var endDate sql.NullTime

		err := rows.Scan(
			&event.ID, &event.Name, &event.Description, &event.EventType,
			&event.StartDate, &endDate, &event.Location, &event.OrganizerUID,
			&event.SigningMethod, &event.RequireApproval, &event.IsActive,
			&event.CreatedAt, &event.UpdatedAt,
		)

		if err != nil {
			return nil, err
		}

		if endDate.Valid {
			event.EndDate = &endDate.Time
		}

		events = append(events, &event)
	}

	return events, rows.Err()
}

// CertificateRepository handles DOD PKI certificate management
type CertificateRepository struct {
	db *sql.DB
}

func NewCertificateRepository(db *sql.DB) *CertificateRepository {
	return &CertificateRepository{db: db}
}

func (r *CertificateRepository) GetRootCertificates() ([]*model.DODRootCert, error) {
	query := `
		SELECT certificate_name, certificate_der, thumbprint, issuer_cn, valid_from, valid_to, is_active
		FROM dot_root_certificates
		WHERE is_active = true
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []*model.DODRootCert

	for rows.Next() {
		var cert model.DODRootCert
		err := rows.Scan(
			&cert.CertificateName, &cert.CertificateDER, &cert.Thumbprint,
			&cert.IssuerCN, &cert.ValidFrom, &cert.ValidTo, &cert.IsActive,
		)
		if err != nil {
			return nil, err
		}

		certs = append(certs, &cert)
	}

	return certs, rows.Err()
}

func (r *CertificateRepository) IsRevokedBySerialNumber(issuerDN, serialNumber string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM certificate_revocation_list
			WHERE issuer_dn = $1 AND $2 = ANY(revoked_serials)
		)
	`

	var isRevoked bool
	err := r.db.QueryRow(query, issuerDN, serialNumber).Scan(&isRevoked)
	return isRevoked, err
}

// DocumentRepository handles PDF document operations
type DocumentRepository struct {
	db *sql.DB
}

func NewDocumentRepository(db *sql.DB) *DocumentRepository {
	return &DocumentRepository{db: db}
}

func (r *DocumentRepository) CreateDocument(doc *model.Document) error {
	query := `
		INSERT INTO documents (event_id, document_type, pdf_content, pdf_hash, pdf_size, created_by_uid, expires_at, is_template)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at
	`

	return r.db.QueryRow(
		query,
		doc.EventID,
		doc.DocumentType,
		doc.PDFContent,
		doc.PDFHash,
		doc.PDFSize,
		doc.CreatedByUID,
		doc.ExpiresAt,
		doc.IsTemplate,
	).Scan(&doc.ID, &doc.CreatedAt)
}

func (r *DocumentRepository) GetDocumentByID(docID uuid.UUID) (*model.Document, error) {
	query := `
		SELECT id, event_id, document_type, pdf_content, pdf_hash, pdf_size, created_at, expires_at, is_template, created_by_uid
		FROM documents
		WHERE id = $1
	`

	var doc model.Document
	var expiresAt sql.NullTime

	err := r.db.QueryRow(query, docID).Scan(
		&doc.ID, &doc.EventID, &doc.DocumentType, &doc.PDFContent, &doc.PDFHash,
		&doc.PDFSize, &doc.CreatedAt, &expiresAt, &doc.IsTemplate, &doc.CreatedByUID,
	)

	if expiresAt.Valid {
		doc.ExpiresAt = &expiresAt.Time
	}

	return &doc, err
}
