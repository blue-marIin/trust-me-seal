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

	// TODO: Do not pass outputDir to generateCert functions - handle output writing in main
	// 	^ Unsure of whether this is a good idea anymore
	// TODO: Get DNS and IP to work - separate params, IP optional?
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

	// Generate print server's cert signed by CA's cert and PK, with given DNS and optionally IP
	// Valid for 1 year from time of generation
	generateServerCertificate(*printerDns, *outputBaseDir, *passphrase, caCert, caKey)

	// Write out server's PK12, PEM and PK files to respective output dirs
	// P12 -> `./{output}`
	// PEM, PK -> `./{output}/clodop`
	fmt.Println("Finished generating certificates - please check the output folder.")
}

func loadConfig(caConfigPath string) (CAConfig, error) {
	var config CAConfig
	var err error

	configData, err := os.ReadFile(caConfigPath)
	if err != nil {
		log.Fatalf("Failed to load CA config file: %v", err)
	}

	if err := json.Unmarshal(configData, &config); err != nil {
		log.Fatalf("Failed to parse CA config JSON: %v", err)
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

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	caPfxData, err := pkcs12.Modern.Encode(priv, cert, nil, passphrase)
	if err != nil {
		log.Fatalf("Failed to encode PKCS12 data: %v", err)
	}
	//os.WriteFile(outputDir+"/TRUSTED_ROOT.p12", pfxData, 0600)

	//certOut, _ := os.Create(outputDir + "/openssl_root_certfile.pem")
	//pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	//certOut.Close()

	// Not outputting CA's private key by default - intended ephemeral/single-use CA cert
	// if exportRootPK {
	// 	keyOut, _ := os.Create(outputDir + "/ca_key.pem")
	// 	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	// 	keyOut.Close()
	// }

	return cert, priv, caPfxData, err
}

func generateServerCertificate(ipStr string, outputDir string, passphrase string, caCert *x509.Certificate, caKey *rsa.PrivateKey) error {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate server private key: %w", err)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Fatalf("Invalid IP address: %s\n", ipStr)
	}

	template := x509.Certificate{
		SerialNumber: bigInt(),
		Subject: pkix.Name{
			CommonName: ipStr, // deprecated
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		IPAddresses: []net.IP{ip},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	var certDER []byte
	if caCert != nil && caKey != nil {
		certDER, _ = x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	}

	cert, _ := x509.ParseCertificate(certDER)

	pfxData, _ := pkcs12.Modern.Encode(priv, cert, nil, passphrase)
	os.WriteFile(outputDir+serverPK12Filename, pfxData, 0600)

	certOut, _ := os.Create(outputDir + serverPEMFilename)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	certOut.Close()

	keyOut, _ := os.Create(outputDir + serverPrivateKeyFilename)
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

	err = os.WriteFile(filepath.Join(outputPath, caPK12Filename), pfxData, 0600)
	if err != nil {
		log.Fatalf("Failed to write CA PKCS12 file: %v", err)
	}

	certOut, err := os.Create(filepath.Join(outputPath, caPEMFilename))
	if err != nil {
		return fmt.Errorf("failed to create CA PEM file: %w", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

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
