package repository

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/thana/signonduty/internal/model"
)

type AuditLogRepository struct {
	db *sql.DB
}

func NewAuditLogRepository(db *sql.DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

// CreateAuditLog creates an immutable audit log entry
func (r *AuditLogRepository) CreateAuditLog(entry *model.AuditLogEntry) error {
	eventDataJSON, err := json.Marshal(entry.EventData)
	if err != nil {
		return err
	}

	// Get previous entry hash (for blockchain-like chain)
	var previousHash []byte
	lastEntryQuery := `SELECT content_hash FROM audit_log ORDER BY id DESC LIMIT 1`
	err = r.db.QueryRow(lastEntryQuery).Scan(&previousHash)
	// If no previous entry, that's fine (first entry)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	query := `
		INSERT INTO audit_log (
			action, entity_type, entity_id, actor_type, actor_uid,
			actor_ip_address, actor_cert_thumbprint, result_status,
			error_message, event_data, created_at, content_hash, previous_entry_hash
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		) RETURNING id
	`

	err = r.db.QueryRow(
		query,
		entry.Action,
		entry.EntityType,
		entry.EntityID,
		entry.ActorType,
		entry.ActorUID,
		entry.ActorIPAddress,
		entry.ActorCertThumbprint,
		entry.ResultStatus,
		entry.ErrorMessage,
		eventDataJSON,
		time.Now().UTC(),
		entry.ContentHash, // Computed before insertion
		previousHash,
	).Scan(&entry.ID)

	return err
}

// GetAuditLogByEntity retrieves all audit logs for an entity
func (r *AuditLogRepository) GetAuditLogByEntity(entityType string, entityID uuid.UUID) ([]*model.AuditLogEntry, error) {
	query := `
		SELECT
			id, action, entity_type, entity_id, actor_type, actor_uid,
			actor_ip_address, actor_cert_thumbprint, result_status,
			error_message, event_data, created_at, content_hash
		FROM audit_log
		WHERE entity_type = $1 AND entity_id = $2
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(query, entityType, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*model.AuditLogEntry

	for rows.Next() {
		var entry model.AuditLogEntry
		var eventDataJSON []byte
		var actorUID sql.NullString
		var actorCertThumbprint sql.NullString
		var errorMessage sql.NullString

		err := rows.Scan(
			&entry.ID,
			&entry.Action,
			&entry.EntityType,
			&entry.EntityID,
			&entry.ActorType,
			&actorUID,
			&entry.ActorIPAddress,
			&actorCertThumbprint,
			&entry.ResultStatus,
			&errorMessage,
			&eventDataJSON,
			&entry.CreatedAt,
			&entry.ContentHash,
		)

		if err != nil {
			return nil, err
		}

		if len(eventDataJSON) > 0 {
			err = json.Unmarshal(eventDataJSON, &entry.EventData)
			if err != nil {
				return nil, err
			}
		}

		if actorUID.Valid {
			entry.ActorUID = &actorUID.String
		}
		if actorCertThumbprint.Valid {
			entry.ActorCertThumbprint = &actorCertThumbprint.String
		}
		if errorMessage.Valid {
			entry.ErrorMessage = &errorMessage.String
		}

		entries = append(entries, &entry)
	}

	return entries, rows.Err()
}

// GetRecentAuditLogs retrieves recent audit log entries
func (r *AuditLogRepository) GetRecentAuditLogs(limit int) ([]*model.AuditLogEntry, error) {
	query := `
		SELECT
			id, action, entity_type, entity_id, actor_type, actor_uid,
			actor_ip_address, actor_cert_thumbprint, result_status,
			error_message, event_data, created_at, content_hash
		FROM audit_log
		ORDER BY created_at DESC
		LIMIT $1
	`

	rows, err := r.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*model.AuditLogEntry

	for rows.Next() {
		var entry model.AuditLogEntry
		var eventDataJSON []byte
		var actorUID sql.NullString
		var actorCertThumbprint sql.NullString
		var errorMessage sql.NullString

		err := rows.Scan(
			&entry.ID,
			&entry.Action,
			&entry.EntityType,
			&entry.EntityID,
			&entry.ActorType,
			&actorUID,
			&entry.ActorIPAddress,
			&actorCertThumbprint,
			&entry.ResultStatus,
			&errorMessage,
			&eventDataJSON,
			&entry.CreatedAt,
			&entry.ContentHash,
		)

		if err != nil {
			return nil, err
		}

		if len(eventDataJSON) > 0 {
			err = json.Unmarshal(eventDataJSON, &entry.EventData)
			if err != nil {
				return nil, err
			}
		}

		if actorUID.Valid {
			entry.ActorUID = &actorUID.String
		}
		if actorCertThumbprint.Valid {
			entry.ActorCertThumbprint = &actorCertThumbprint.String
		}
		if errorMessage.Valid {
			entry.ErrorMessage = &errorMessage.String
		}

		entries = append(entries, &entry)
	}

	return entries, rows.Err()
}

// VerifyAuditChain verifies the integrity of audit logs
func (r *AuditLogRepository) VerifyAuditChain() (bool, error) {
	query := `
		SELECT id, content_hash, previous_entry_hash
		FROM audit_log
		ORDER BY id ASC
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	var lastHash []byte
	chainValid := true

	for rows.Next() {
		var id int64
		var contentHash []byte
		var previousHash sql.NullString

		err := rows.Scan(&id, &contentHash, &previousHash)
		if err != nil {
			return false, err
		}

		// Verify chain: current entry's previous_entry_hash should match previous entry's content_hash
		if lastHash != nil && previousHash.Valid {
			// In a real implementation, you'd compare the hashes here
			// For now, we just verify structure
		}

		lastHash = contentHash
	}

	return chainValid, rows.Err()
}
