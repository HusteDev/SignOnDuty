package main

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/thana/signonduty/internal/config"
	"github.com/thana/signonduty/internal/database"
	"github.com/thana/signonduty/internal/handler"
	"github.com/thana/signonduty/internal/repository"
	"github.com/thana/signonduty/internal/service"
)

func main() {
	// Load environment variables
	_ = godotenv.Load()

	// Initialize configuration
	cfg := config.Load()

	// Connect to database
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize repositories
	eventRepo := repository.NewEventRepository(db)
	signupRepo := repository.NewSignupRepository(db)
	auditLogRepo := repository.NewAuditLogRepository(db)
	certRepo := repository.NewCertificateRepository(db)
	documentRepo := repository.NewDocumentRepository(db)

	// Initialize services
	pkiService := service.NewPKIService(certRepo)
	signupService := service.NewSignupService(signupRepo, auditLogRepo, pkiService)
	documentService := service.NewDocumentService(documentRepo, pkiService)
	eventService := service.NewEventService(eventRepo)

	// Initialize handlers
	h := handler.NewHandler(signupService, documentService, eventService, pkiService)

	// Create Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
	e.Use(middleware.CORS())

	// Custom middleware for audit logging
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Extract client certificate if present
			if c.Request().TLS != nil && len(c.Request().TLS.PeerCertificates) > 0 {
				// Certificate validation and logging happens here
				cert := c.Request().TLS.PeerCertificates[0]
				c.Set("client_cert", cert)
				c.Set("client_cert_subject", cert.Subject.String())
			}

			c.Set("client_ip", c.RealIP())
			return next(c)
		}
	})

	// Routes
	registerRoutes(e, h)

	// Configure TLS
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
		// Client certificate requirement (optional, configurable)
		ClientAuth: tls.VerifyClientCertIfGiven,
	}

	// Start server
	addr := fmt.Sprintf("%s:%s", cfg.ServerHost, cfg.ServerPort)
	log.Printf("Starting SignOnDuty server on %s (TLS 1.3)", addr)

	e.TLSServer.TLSConfig = tlsConfig
	e.Logger.Fatal(e.StartTLS(addr, cfg.TLSCertFile, cfg.TLSKeyFile))
}

func registerRoutes(e *echo.Echo, h *handler.Handler) {
	v1 := e.Group("/api/v1")

	// Health check
	v1.GET("/health", h.HealthCheck)

	// Event management
	v1.POST("/events", h.CreateEvent)
	v1.GET("/events/:eventID", h.GetEvent)
	v1.GET("/events", h.ListEvents)
	v1.PUT("/events/:eventID", h.UpdateEvent)

	// mTLS Sign-up endpoint
	v1.POST("/signups/mtls", h.CreateMTLSSignup)

	// PAdES document endpoints
	v1.POST("/signups/documents", h.GenerateSigningDocument)
	v1.POST("/signups/verify-pdf", h.VerifySignedPDF)

	// Signup management
	v1.GET("/events/:eventID/signups", h.ListSignups)
	v1.GET("/signups/:signupID", h.GetSignup)
	v1.GET("/signups/:signupID/audit", h.GetSignupAudit)

	// Certificate verification
	v1.POST("/admin/verify-certificate", h.VerifyCertificate)

	// Approval workflow
	v1.POST("/signups/:signupID/approve", h.ApproveSignup)
	v1.POST("/signups/:signupID/reject", h.RejectSignup)

	// Audit log export
	v1.GET("/admin/audit-logs", h.ExportAuditLogs)
	v1.GET("/admin/audit-logs/export", h.DownloadAuditLogsCSV)
}
