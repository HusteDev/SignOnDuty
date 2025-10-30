package handler

import (
	"crypto/x509"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/thana/signonduty/internal/model"
	"github.com/thana/signonduty/internal/service"
)

type Handler struct {
	signupService    *service.SignupService
	documentService  *service.DocumentService
	eventService     *service.EventService
	pkiService       *service.PKIService
}

func NewHandler(
	signupService *service.SignupService,
	documentService *service.DocumentService,
	eventService *service.EventService,
	pkiService *service.PKIService,
) *Handler {
	return &Handler{
		signupService:   signupService,
		documentService: documentService,
		eventService:    eventService,
		pkiService:      pkiService,
	}
}

// HealthCheck returns server health status
func (h *Handler) HealthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status": "healthy",
	})
}

// CreateMTLSSignup handles mTLS sign-up requests
func (h *Handler) CreateMTLSSignup(c echo.Context) error {
	// Extract client certificate from TLS connection
	var clientCert *x509.Certificate
	if c.Request().TLS != nil && len(c.Request().TLS.PeerCertificates) > 0 {
		clientCert = c.Request().TLS.PeerCertificates[0]
	}

	if clientCert == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Client certificate is required for mTLS signup",
		})
	}

	// Parse request
	var req model.MTLSSignUpRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request",
		})
	}

	// Extract event ID from path or query
	eventID, err := uuid.Parse(c.Param("eventID"))
	if err != nil {
		// Try to get from request body or query
		eventIDStr := c.QueryParam("eventID")
		if eventIDStr != "" {
			eventID, err = uuid.Parse(eventIDStr)
			if err != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{
					"error": "Invalid event ID",
				})
			}
		} else {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "Event ID is required",
			})
		}
	}

	clientIP := c.RealIP()

	// Create signup
	signup, err := h.signupService.CreateMTLSSignup(eventID, clientCert, clientIP)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	// Generate verification token (in production, this would be cryptographically signed)
	verifyToken := uuid.New().String()

	return c.JSON(http.StatusCreated, model.SignUpResponse{
		SignUpID:    signup.ID.String(),
		Timestamp:   signup.CreatedAt,
		SignerName:  signup.SignerName,
		VerifyToken: verifyToken,
	})
}

// GenerateSigningDocument generates an unsigned PDF for signing
func (h *Handler) GenerateSigningDocument(c echo.Context) error {
	var req model.DocumentRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request",
		})
	}

	eventID, err := uuid.Parse(req.EventID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid event ID",
		})
	}

	// For now, use system as creator
	createdByUID := "system"

	doc, err := h.documentService.GenerateSigningDocument(
		eventID,
		req.EventName,
		req.EventDate,
		createdByUID,
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	// Return PDF in base64
	// In production, would return proper PDF response
	return c.JSON(http.StatusOK, model.DocumentResponse{
		DocumentID: doc.ID.String(),
		PDFBase64:  "", // Would be base64 encoded PDF
		DocumentURL: "", // Would be S3 pre-signed URL
	})
}

// VerifySignedPDF verifies a signed PDF document
func (h *Handler) VerifySignedPDF(c echo.Context) error {
	var req model.PDFVerificationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request",
		})
	}

	if req.DocumentID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Document ID is required",
		})
	}

	_, err := uuid.Parse(req.DocumentID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid document ID",
		})
	}

	// Decode PDF from base64 or file upload
	// pdfData, err := base64.StdEncoding.DecodeString(req.PDFBase64)
	// if err != nil {
	//     return c.JSON(http.StatusBadRequest, map[string]string{
	//         "error": "Invalid PDF encoding",
	//     })
	// }

	// For now, return not implemented
	return c.JSON(http.StatusNotImplemented, map[string]string{
		"error": "PAdES signature verification not yet implemented",
	})
}

// GetSignup retrieves a signup record
func (h *Handler) GetSignup(c echo.Context) error {
	signupID, err := uuid.Parse(c.Param("signupID"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid signup ID",
		})
	}

	signup, err := h.signupService.GetSignupByID(signupID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "Signup not found",
		})
	}

	return c.JSON(http.StatusOK, signup)
}

// ListSignups lists signups for an event
func (h *Handler) ListSignups(c echo.Context) error {
	eventID, err := uuid.Parse(c.Param("eventID"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid event ID",
		})
	}

	signups, err := h.signupService.ListSignupsByEventID(eventID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, signups)
}

// GetSignupAudit retrieves audit trail for a signup
func (h *Handler) GetSignupAudit(c echo.Context) error {
	signupID, err := uuid.Parse(c.Param("signupID"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid signup ID",
		})
	}

	auditTrail, err := h.signupService.GetSignupAuditTrail(signupID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, auditTrail)
}

// CreateEvent creates a new event
func (h *Handler) CreateEvent(c echo.Context) error {
	var event model.Event
	if err := c.Bind(&event); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request",
		})
	}

	// Set organizer to authenticated user
	// In production, extract from JWT or certificate
	event.OrganizerUID = "system"

	err := h.eventService.CreateEvent(&event)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusCreated, event)
}

// GetEvent retrieves an event
func (h *Handler) GetEvent(c echo.Context) error {
	eventID, err := uuid.Parse(c.Param("eventID"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid event ID",
		})
	}

	event, err := h.eventService.GetEventByID(eventID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "Event not found",
		})
	}

	return c.JSON(http.StatusOK, event)
}

// ListEvents lists all events
func (h *Handler) ListEvents(c echo.Context) error {
	events, err := h.eventService.ListEvents()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, events)
}

// UpdateEvent updates an event
func (h *Handler) UpdateEvent(c echo.Context) error {
	var event model.Event
	if err := c.Bind(&event); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request",
		})
	}

	err := h.eventService.UpdateEvent(&event)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, event)
}

// VerifyCertificate verifies a certificate (admin endpoint)
func (h *Handler) VerifyCertificate(c echo.Context) error {
	// Admin only endpoint
	var req map[string]string
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request",
		})
	}

	// Parse certificate PEM/DER
	// For now, not implemented
	return c.JSON(http.StatusNotImplemented, map[string]string{
		"error": "Certificate verification endpoint not yet fully implemented",
	})
}

// ApproveSignup approves a signup (approver endpoint)
func (h *Handler) ApproveSignup(c echo.Context) error {
	signupID, err := uuid.Parse(c.Param("signupID"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid signup ID",
		})
	}

	var req map[string]string
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request",
		})
	}

	approverUID := "system" // Would be extracted from auth
	notes := req["notes"]

	err = h.signupService.ApproveSignup(signupID, approverUID, notes)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"status": "approved",
	})
}

// RejectSignup rejects a signup (approver endpoint)
func (h *Handler) RejectSignup(c echo.Context) error {
	signupID, err := uuid.Parse(c.Param("signupID"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid signup ID",
		})
	}

	var req map[string]string
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request",
		})
	}

	approverUID := "system" // Would be extracted from auth
	notes := req["notes"]

	err = h.signupService.RejectSignup(signupID, approverUID, notes)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"status": "rejected",
	})
}

// ExportAuditLogs exports audit logs (admin endpoint)
func (h *Handler) ExportAuditLogs(c echo.Context) error {
	// Admin only
	// Would retrieve and return audit logs
	return c.JSON(http.StatusNotImplemented, map[string]string{
		"error": "Audit log export not yet implemented",
	})
}

// DownloadAuditLogsCSV downloads audit logs as CSV (admin endpoint)
func (h *Handler) DownloadAuditLogsCSV(c echo.Context) error {
	// Admin only
	// Would generate and return CSV file
	return c.JSON(http.StatusNotImplemented, map[string]string{
		"error": "CSV export not yet implemented",
	})
}
