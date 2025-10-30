package service

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/thana/signonduty/internal/model"
	"github.com/thana/signonduty/internal/repository"
)

// DocumentService handles PDF document operations for PAdES signing
type DocumentService struct {
	documentRepo *repository.DocumentRepository
	pkiService   *PKIService
}

func NewDocumentService(
	documentRepo *repository.DocumentRepository,
	pkiService *PKIService,
) *DocumentService {
	return &DocumentService{
		documentRepo: documentRepo,
		pkiService:   pkiService,
	}
}

// GenerateSigningDocument creates an unsigned PDF for signing
func (s *DocumentService) GenerateSigningDocument(
	eventID uuid.UUID,
	eventName string,
	eventDate time.Time,
	createdByUID string,
) (*model.Document, error) {
	// Generate PDF document
	// In production, this would use a PDF library like pdfcpu
	// to create a structured form with a signature field

	// For now, create a stub PDF
	pdfContent := s.generateStubPDF(eventName, eventDate)

	pdfHash := sha256.Sum256(pdfContent)

	doc := &model.Document{
		EventID:       eventID,
		DocumentType:  "sign_in_sheet",
		PDFContent:    pdfContent,
		PDFHash:       pdfHash[:],
		PDFSize:       int64(len(pdfContent)),
		CreatedByUID:  createdByUID,
		IsTemplate:    false,
	}

	err := s.documentRepo.CreateDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("failed to create document: %w", err)
	}

	return doc, nil
}

// VerifySignedPDF verifies a PAdES-signed PDF
func (s *DocumentService) VerifySignedPDF(
	documentID uuid.UUID,
	signedPDFData []byte,
) (*model.SignatureValidation, error) {
	// 1. Retrieve original unsigned document
	_, err := s.documentRepo.GetDocumentByID(documentID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve original document: %w", err)
	}

	// 2. Extract certificate and signature from signed PDF
	// This requires parsing CMS/PKCS#7 structure from PDF
	// pdfcpu library can help here
	// certs, signature, err := s.extractSignatureFromPDF(signedPDFData)
	// if err != nil {
	//     return nil, fmt.Errorf("failed to extract signature: %w", err)
	// }

	// 3. Verify PDF integrity (content hasn't changed)
	// This would hash the document data from the PDF
	// and compare with the signature

	// 4. Validate signer certificate
	// validation, err := s.pkiService.ValidateCAC(certs[0])
	// if err != nil {
	//     return nil, fmt.Errorf("signature certificate validation failed: %w", err)
	// }

	// For now, return stub validation
	return &model.SignatureValidation{
		Valid:     false,
		Timestamp: time.Now().UTC(),
	}, fmt.Errorf("PAdES signature verification not yet implemented")
}

// GetDocumentByID retrieves a document
func (s *DocumentService) GetDocumentByID(documentID uuid.UUID) (*model.Document, error) {
	return s.documentRepo.GetDocumentByID(documentID)
}

// generateStubPDF creates a minimal PDF for testing
// In production, this would use pdfcpu to create a properly formatted PDF
func (s *DocumentService) generateStubPDF(eventName string, eventDate time.Time) []byte {
	// Minimal PDF structure
	pdfContent := []byte(`%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length 100 >>
stream
BT
/F1 12 Tf
50 750 Td
(Sign-In Sheet) Tj
0 -50 Td
(Event: ` + eventName + `) Tj
ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000233 00000 n
0000000333 00000 n
trailer
<< /Size 6 /Root 1 0 R >>
startxref
412
%%EOF
`)

	return pdfContent
}

// VerifyDocumentHash verifies a document's integrity using stored hash
func (s *DocumentService) VerifyDocumentHash(doc *model.Document) (bool, error) {
	computedHash := sha256.Sum256(doc.PDFContent)
	// Compare hash bytes
	for i, b := range computedHash[:] {
		if i < len(doc.PDFHash) && doc.PDFHash[i] != b {
			return false, nil
		}
	}
	return true, nil
}
