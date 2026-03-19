package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// Let's Encrypt production directory
	letsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"
)

// ACMEDirectory represents the ACME directory response.
type ACMEDirectory struct {
	NewNonce   string            `json:"newNonce"`
	NewAccount string            `json:"newAccount"`
	NewOrder   string            `json:"newOrder"`
	RevokeCert string            `json:"revokeCert"`
	KeyChange  string            `json:"keyChange"`
	RenewalInfo string           `json:"renewalInfo,omitempty"`
	Meta       map[string]any    `json:"meta,omitempty"`
}

// RenewalInfo represents the ACME ARI response (RFC 9773).
type RenewalInfo struct {
	SuggestedWindow *Window `json:"suggestedWindow"`
	ExplanationURL  string  `json:"explanationURL,omitempty"`
}

// Window represents the suggested renewal window.
type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <certificate-serial-number> [acme-directory-url]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nThe serial number should be in hex (colon-separated or plain).\n")
		fmt.Fprintf(os.Stderr, "Example: %s 04:ab:cd:ef:12:34 \n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s 04abcdef1234\n", os.Args[0])
		os.Exit(1)
	}

	serialHex := os.Args[1]
	directoryURL := letsEncryptDirectory
	if len(os.Args) >= 3 {
		directoryURL = os.Args[2]
	}

	// Normalize the serial: remove colons, leading zeros
	serialHex = strings.ReplaceAll(serialHex, ":", "")

	serialInt := new(big.Int)
	_, ok := serialInt.SetString(serialHex, 16)
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: invalid hex serial number: %s\n", serialHex)
		os.Exit(1)
	}

	fmt.Printf("Serial (hex): %s\n", serialHex)
	fmt.Printf("Serial (dec): %s\n", serialInt.String())
	fmt.Printf("Directory:    %s\n\n", directoryURL)

	// Step 1: Fetch the ACME directory
	dir, err := fetchDirectory(directoryURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching ACME directory: %v\n", err)
		os.Exit(1)
	}

	if dir.RenewalInfo == "" {
		fmt.Fprintf(os.Stderr, "Error: ACME directory does not advertise renewalInfo endpoint\n")
		os.Exit(1)
	}
	fmt.Printf("RenewalInfo endpoint: %s\n\n", dir.RenewalInfo)

	// Step 2: Fetch the certificate via ACME cert URL
	// Let's Encrypt certificate URL pattern: <directory-base>/acme/cert/<serial-hex>
	certURL := buildCertURL(directoryURL, serialHex)
	fmt.Printf("Fetching certificate from: %s\n", certURL)

	certPEM, err := fetchCertificate(certURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching certificate: %v\n", err)
		os.Exit(1)
	}

	cert, err := parseCertificate(certPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing certificate: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Certificate Subject: %s\n", cert.Subject.CommonName)
	fmt.Printf("Certificate Issuer:  %s\n", cert.Issuer.CommonName)
	fmt.Printf("Not Before:          %s\n", cert.NotBefore)
	fmt.Printf("Not After:           %s\n", cert.NotAfter)
	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS Names:           %s\n", strings.Join(cert.DNSNames, ", "))
	}
	fmt.Println()

	// Step 3: Build the ARI CertID and fetch renewal info
	ariCertID, err := buildARICertID(cert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building ARI CertID: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("ARI CertID: %s\n", ariCertID)

	renewalInfo, retryAfter, err := fetchRenewalInfo(dir.RenewalInfo, ariCertID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching renewal info: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n=== Renewal Info ===")
	if renewalInfo.SuggestedWindow != nil {
		fmt.Printf("Suggested Window Start: %s\n", renewalInfo.SuggestedWindow.Start)
		fmt.Printf("Suggested Window End:   %s\n", renewalInfo.SuggestedWindow.End)
	}
	if renewalInfo.ExplanationURL != "" {
		fmt.Printf("Explanation URL: %s\n", renewalInfo.ExplanationURL)
	}
	if retryAfter != "" {
		fmt.Printf("Retry-After:     %s\n", retryAfter)
	}

	// Also print raw JSON
	raw, _ := json.MarshalIndent(renewalInfo, "", "  ")
	fmt.Printf("\nRaw JSON:\n%s\n", string(raw))
}

func fetchDirectory(url string) (*ACMEDirectory, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, string(body))
	}

	var dir ACMEDirectory
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		return nil, fmt.Errorf("decoding directory: %w", err)
	}
	return &dir, nil
}

func buildCertURL(directoryURL, serialHex string) string {
	// For Let's Encrypt: https://acme-v02.api.letsencrypt.org/acme/cert/<serial>
	// Derive base from directory URL by removing /directory
	base := strings.TrimSuffix(directoryURL, "/directory")
	return fmt.Sprintf("%s/acme/cert/%s", base, strings.ToLower(serialHex))
}

func fetchCertificate(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/pem-certificate-chain")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, string(body))
	}

	return body, nil
}

func parseCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in certificate response")
	}
	return x509.ParseCertificate(block.Bytes)
}

// buildARICertID constructs the ARI CertID per RFC 9773.
// The CertID is: base64url(AKI) "." base64url(Serial)
// where AKI is the Authority Key Identifier's keyIdentifier field and Serial
// is the value bytes of the DER-encoded serial number (without tag/length).
func buildARICertID(cert *x509.Certificate) (string, error) {
	aki := cert.AuthorityKeyId
	if len(aki) == 0 {
		return "", fmt.Errorf("certificate has no Authority Key Identifier extension")
	}

	// Serial number as DER INTEGER value bytes. DER uses two's complement,
	// so a positive integer with the high bit set needs a leading 0x00.
	serialBytes := cert.SerialNumber.Bytes()
	if len(serialBytes) > 0 && serialBytes[0]&0x80 != 0 {
		serialBytes = append([]byte{0x00}, serialBytes...)
	}

	akiEncoded := base64.RawURLEncoding.EncodeToString(aki)
	serialEncoded := base64.RawURLEncoding.EncodeToString(serialBytes)

	return akiEncoded + "." + serialEncoded, nil
}

func fetchRenewalInfo(renewalInfoURL, certID string) (*RenewalInfo, string, error) {
	url := renewalInfoURL + "/" + certID

	resp, err := http.Get(url)
	if err != nil {
		return nil, "", fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, string(body))
	}

	retryAfter := resp.Header.Get("Retry-After")

	var info RenewalInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, "", fmt.Errorf("decoding renewal info: %w", err)
	}

	return &info, retryAfter, nil
}
