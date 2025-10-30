package service

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/thana/signonduty/internal/model"
	"github.com/thana/signonduty/internal/repository"
)

// PKIService handles Public Key Infrastructure operations for CAC certificates
type PKIService struct {
	certRepo *repository.CertificateRepository
	dotRoots []*x509.Certificate
}

func NewPKIService(certRepo *repository.CertificateRepository) *PKIService {
	return &PKIService{
		certRepo: certRepo,
		dotRoots: make([]*x509.Certificate, 0),
	}
}

// Initialize loads DOD root certificates from database
func (s *PKIService) Initialize() error {
	rootCerts, err := s.certRepo.GetRootCertificates()
	if err != nil {
		return fmt.Errorf("failed to load DOD root certificates: %w", err)
	}

	for _, rootCertData := range rootCerts {
		cert, err := x509.ParseCertificate(rootCertData.CertificateDER)
		if err != nil {
			return fmt.Errorf("failed to parse certificate %s: %w", rootCertData.CertificateName, err)
		}
		s.dotRoots = append(s.dotRoots, cert)
	}

	return nil
}

// ValidateCAC validates a CAC certificate and extracts identity information
func (s *PKIService) ValidateCAC(cert *x509.Certificate) (*model.CertificateValidation, error) {
	result := &model.CertificateValidation{
		ValidationTime: time.Now().UTC(),
	}

	// 1. Check certificate dates
	now := time.Now().UTC()
	if now.Before(cert.NotBefore) {
		result.ValidationStatus = "not_yet_valid"
		result.ErrorMessage = fmt.Sprintf("Certificate not valid until %v", cert.NotBefore)
		return result, nil
	}

	if now.After(cert.NotAfter) {
		result.ValidationStatus = "expired"
		result.ErrorMessage = fmt.Sprintf("Certificate expired at %v", cert.NotAfter)
		return result, nil
	}

	// 2. Validate certificate chain
	opts := x509.VerifyOptions{
		Roots:       s.buildTrustStore(),
		CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		result.ValidationStatus = "untrusted_root"
		result.ErrorMessage = fmt.Sprintf("Certificate chain validation failed: %v", err)
		return result, nil
	}

	if len(chains) == 0 {
		result.ValidationStatus = "invalid_chain"
		result.ErrorMessage = "No valid certificate chain found"
		return result, nil
	}

	// 3. Extract CAC identity information
	identity := s.extractCACIdentity(cert)
	if identity == nil {
		result.ValidationStatus = "invalid_subject"
		result.ErrorMessage = "Failed to extract CAC identity from certificate"
		return result, nil
	}

	// 4. Build certificate chain for the result
	result.CertificateChain = chains[0]

	// 5. Check for revocation (optional, would require CRL/OCSP checks)
	// revoked, err := s.isCertificateRevoked(cert)
	// if err != nil || revoked {
	//     result.ValidationStatus = "revoked"
	//     return result, nil
	// }

	// Certificate is valid
	result.Valid = true
	result.Identity = identity
	result.ValidationStatus = "valid"

	return result, nil
}

// ExtractIdentityFromChain validates and extracts identity from a certificate chain
func (s *PKIService) ExtractIdentityFromChain(certChain []*x509.Certificate) (*model.CACIdentity, error) {
	if len(certChain) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}

	leafCert := certChain[0]

	// Validate the leaf certificate
	result, err := s.ValidateCAC(leafCert)
	if err != nil {
		return nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	if !result.Valid {
		return nil, fmt.Errorf("certificate validation failed: %s", result.ErrorMessage)
	}

	return result.Identity, nil
}

// extractCACIdentity extracts CAC identity from certificate subject
func (s *PKIService) extractCACIdentity(cert *x509.Certificate) *model.CACIdentity {
	// CAC certificates have a specific subject format:
	// CN=LASTNAME.FIRSTNAME.SSN, OU=Organization, O=U.S. Government, C=US

	subject := cert.Subject
	cn := subject.CommonName

	if cn == "" {
		return nil
	}

	// Parse CN: "LASTNAME.FIRSTNAME.SSN"
	parts := strings.Split(cn, ".")
	if len(parts) < 3 {
		return nil
	}

	lastName := parts[0]
	firstName := parts[1]
	ssn := parts[2]

	// Compute certificate thumbprint (SHA256)
	certDER := cert.Raw
	hash := sha256.Sum256(certDER)
	thumbprint := hex.EncodeToString(hash[:])

	identity := &model.CACIdentity{
		FirstName:         firstName,
		LastName:          lastName,
		SSN:               ssn,
		Organization:      subject.Organization[0],
		DistinguishedName: cert.Subject.String(),
		Thumbprint:        thumbprint,
	}

	return identity
}

// GetCertificateThumbprint computes SHA256 thumbprint of a certificate
func (s *PKIService) GetCertificateThumbprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// buildTrustStore creates an x509 CertPool from DOD roots
func (s *PKIService) buildTrustStore() *x509.CertPool {
	pool := x509.NewCertPool()

	for _, cert := range s.dotRoots {
		pool.AddCert(cert)
	}

	return pool
}

// ValidateCertificateChain validates an entire certificate chain
func (s *PKIService) ValidateCertificateChain(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	// Validate each certificate in the chain
	for i, cert := range chain {
		now := time.Now().UTC()

		if now.Before(cert.NotBefore) {
			return fmt.Errorf("certificate[%d] not valid until %v", i, cert.NotBefore)
		}

		if now.After(cert.NotAfter) {
			return fmt.Errorf("certificate[%d] expired at %v", i, cert.NotAfter)
		}

		// Verify signatures (if not the root)
		if i > 0 {
			issuerCert := chain[i-1]
			err := issuerCert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
			if err != nil {
				return fmt.Errorf("certificate[%d] signature verification failed: %w", i, err)
			}
		}
	}

	// Verify the root is trusted
	rootCert := chain[len(chain)-1]
	isTrusted := false

	for _, trustedRoot := range s.dotRoots {
		if rootCert.Equal(trustedRoot) {
			isTrusted = true
			break
		}
	}

	if !isTrusted {
		return fmt.Errorf("root certificate not trusted")
	}

	return nil
}

// IsSelfSigned checks if a certificate is self-signed
func (s *PKIService) IsSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

// GetCertificateInfo returns human-readable certificate information
func (s *PKIService) GetCertificateInfo(cert *x509.Certificate) map[string]interface{} {
	return map[string]interface{}{
		"subject":             cert.Subject.String(),
		"issuer":              cert.Issuer.String(),
		"serial_number":       cert.SerialNumber.String(),
		"not_before":          cert.NotBefore,
		"not_after":           cert.NotAfter,
		"signature_algorithm": cert.SignatureAlgorithm.String(),
		"public_key_algorithm": cert.PublicKeyAlgorithm.String(),
		"key_usage":           cert.KeyUsage,
		"extended_key_usage":  cert.ExtKeyUsage,
		"dns_names":           cert.DNSNames,
		"ip_addresses":        cert.IPAddresses,
		"thumbprint_sha256":   s.GetCertificateThumbprint(cert),
	}
}

// ParseCRLDistributionPoint extracts CRL URL from certificate
func (s *PKIService) ParseCRLDistributionPoint(cert *x509.Certificate) ([]string, error) {
	// CRL Distribution Points are in the certificate's CRLDistributionPoints field
	var urls []string

	for _, crlDP := range cert.CRLDistributionPoints {
		if crlDP != "" {
			urls = append(urls, crlDP)
		}
	}

	return urls, nil
}

// ValidateOCSPResponse validates an OCSP response (stub for future implementation)
func (s *PKIService) ValidateOCSPResponse(ocspResponseData []byte) (bool, error) {
	// This would require implementing OCSP validation
	// For now, always return true (no revocation check)
	return true, nil
}

// GetOCSPResponderURL extracts OCSP responder URL from certificate
func (s *PKIService) GetOCSPResponderURL(cert *x509.Certificate) (string, error) {
	// OCSPServer URLs are available in the certificate's OCSPServer field
	if len(cert.OCSPServer) > 0 {
		return cert.OCSPServer[0], nil
	}

	return "", fmt.Errorf("no OCSP responder URL found")
}

// ParseURL is a helper to validate URLs
func (s *PKIService) ParseURL(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Validate scheme is https for PKI operations
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("invalid URL scheme: %s", parsed.Scheme)
	}

	return parsed, nil
}
