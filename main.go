package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

type CAConfig struct {
	Country            string `json:"country"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalUnit"`
	CommonName         string `json:"commonName"`
	ValidForDays       int    `json:"validForDays"`
	IsCA               bool   `json:"isCA"`
	KeyUsageCertSign   bool   `json:"keyUsageCertSign"`
}

const caPK12Filename = "TRUSTED_ROOT.p12"
const caPEMFilename = "openssl_root_certfile.pem" // |
const caPrivateKeyFilename = "root.key"
const serverPK12Filename = "server_certificate.p12"
const serverPEMFilename = "openssl_certfile.pem"        // |- Names are derived from C-Lodop naming
const serverPrivateKeyFilename = "openssl_key_file.key" // |

const serverOutputDir = "clodop" // Subdir of output directory, default './output' - May change this to a more generic name

func main() {
	var err error

	printerDns := flag.String("dns", "", "Print server's hostname")
	passphrase := flag.String("passphrase", "", "Passphrase to encrypt PKCS#12 files")
	outputBaseDir := flag.String("output", "output", "Output file path") // Base of output directory
	caConfigPath := flag.String("ca-config", "ca-config.json", "CA config JSON file location")
	exportCAPK := flag.Bool("export-ca-pk", false, "Export CA private key")
	ipStr := flag.String("ip", "", "Print server's IP address")
	// MAYBE: Add --dry-run flag for preview without writing output
	// MAYBE: Add --valid-for flag to change validity period

	flag.Parse()

	// Check DNS and passphrase flags passed - minimum required to run
	if *printerDns == "" || *passphrase == "" {
		log.Fatalf("You must provide the DNS of the print server PC and a passphrase.\neg: ./trust-me-seal-cli.exe --dns printserver.local --passphrase changeit")
	}

	// Try make `./{output}/clodop` directory & subdirectory for writing output files
	err = os.MkdirAll(filepath.Join(*outputBaseDir, serverOutputDir), os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Try load & parse CA JSON config from `./{ca-config.json}`
	config, err := loadConfig(*caConfigPath)
	if err != nil {
		log.Fatalf("Failed to load CA config JSON file: %v", err)
	}

	// Generate CA PFX from loaded config & passphrase
	caCert, caKey, caPfxData, err := generateCACertificate(config, *passphrase)
	if err != nil {
		log.Fatalf("Failed to generate CA certificate and private key: %v", err)
	}

	// Write out CA's PK12, PEM and optionally PK files to respective output dirs
	// P12, PK -> `./{output}`
	// PEM -> `./{output}/clodop`
	err = writeCAOutput(caCert, caKey, caPfxData, *outputBaseDir, *exportCAPK)
	if err != nil {
		log.Fatalf("Failed to write out CA files: %v", err)
	}

	// TODO: Get DNS and IP to work - separate params, IP optional?
	// Generate print server's cert signed by CA's cert and PK, with given DNS and optionally IP
	// Valid for 1 year from time of generation
	err = generateServerCertificate(caCert, caKey, *ipStr, *outputBaseDir, *passphrase, *printerDns)
	if err != nil {
		log.Fatalf("Failed to generate server certificate and private key: %v", err)
	}

	// Write out server's PK12, PEM and PK files to respective output dirs
	// P12 -> `./{output}`
	// PEM, PK -> `./{output}/clodop`
	err = writeServerOutput()
	if err != nil {
		log.Fatalf("Failed to write out server files: %v", err)
	}

	fmt.Println("Finished generating certificates - please check the output folder.")
}

func loadConfig(caConfigPath string) (CAConfig, error) {
	var config CAConfig
	var err error

	configData, err := os.ReadFile(caConfigPath)
	if err != nil {
		return config, fmt.Errorf("failed to load CA config file: %w", err)
	}

	if err := json.Unmarshal(configData, &config); err != nil {
		return config, fmt.Errorf("failed to parse CA config JSON: %w", err)
	}

	return config, err
}

func generateCACertificate(cfg CAConfig, passphrase string) (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          bigInt(),
		Subject:               pkix.Name{Country: []string{cfg.Country}, Organization: []string{cfg.Organization}, OrganizationalUnit: []string{cfg.OrganizationalUnit}, CommonName: cfg.CommonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, cfg.ValidForDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create CA certificate from template: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse CA certificate from DER: %v", err)
	}

	caPfxData, err := pkcs12.Modern.Encode(priv, cert, nil, passphrase)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode PKCS12 data: %v", err)
	}

	return cert, priv, caPfxData, err
}

func generateServerCertificate(caCert *x509.Certificate, caKey *rsa.PrivateKey, ipStr string, passphrase string, outputBaseDir string, printerDns string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate server private key: %w", err)
	}

	var ipAddresses []net.IP
	if ipStr != "" {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("invalid IP address: %s", ipStr)
		}
		ipAddresses = append(ipAddresses, ip)
	}

	template := x509.Certificate{
		SerialNumber: bigInt(),
		Subject: pkix.Name{
			CommonName: printerDns,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		DNSNames:    []string{printerDns},
		IPAddresses: ipAddresses,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Create server certificate & sign with CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse server certificate: %w", err)
	}
	// This will be broken out into writeServerOutput fun
	pfxData, _ := pkcs12.Modern.Encode(priv, cert, nil, passphrase)
	os.WriteFile(outputBaseDir+serverPK12Filename, pfxData, 0600)

	certOut, _ := os.Create(outputBaseDir + serverPEMFilename)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	certOut.Close()

	keyOut, _ := os.Create(outputBaseDir + serverPrivateKeyFilename)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return nil
}

func bigInt() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}

func writeCAOutput(cert *x509.Certificate, priv *rsa.PrivateKey, pfxData []byte, outputPath string, exportKey bool) error {
	var err error

	// Write CA PK12 file to base output dir `./{output}`
	err = os.WriteFile(filepath.Join(outputPath, caPK12Filename), pfxData, 0600)
	if err != nil {
		log.Fatalf("Failed to write CA PKCS12 file: %v", err)
	}

	// Create PEM file in output subdir `./{output}/clodop`
	certOut, err := os.Create(filepath.Join(outputPath, serverOutputDir, caPEMFilename))
	if err != nil {
		return fmt.Errorf("failed to create CA PEM file: %w", err)
	}
	defer certOut.Close()

	// Write PEM encoded cert to .pem file
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	// If exporting CA's private key enabled, create file and write
	if exportKey {
		keyOut, err := os.Create(filepath.Join(outputPath, caPrivateKeyFilename))
		if err != nil {
			return fmt.Errorf("failed to write CA private key: %w", err)
		}
		defer keyOut.Close()
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	}

	return nil
}

func writeServerOutput() error {
	var err error

	return err
}
